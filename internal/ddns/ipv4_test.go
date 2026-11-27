package ddns

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
)

type fakeIPv4Detector struct {
	ip    net.IP
	err   error
	calls int
}

func (f *fakeIPv4Detector) Detect(ctx context.Context) (net.IP, error) {
	f.calls++
	return f.ip, f.err
}

func ipv4Cfg() config.Config {
	cfg := stableCfg()
	cfg.IPv4Domain = "v4.example.com"
	return cfg
}

func findRecord(res Result, recordType string) *RecordResult {
	for i := range res.Records {
		if res.Records[i].Type == recordType {
			return &res.Records[i]
		}
	}
	return nil
}

func TestIPv4RecordUpdated(t *testing.T) {
	cfg := ipv4Cfg()
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := &fakeCF{
		found: true,
		record: cloudflare.Record{
			ID: "aaaa-1", Type: cloudflare.RecordTypeAAAA, Content: realGUA,
		},
		foundA: true,
		recordA: cloudflare.Record{
			ID: "a-1", Type: cloudflare.RecordTypeA, Content: "1.1.1.1",
		},
	}
	eng := NewEngine(cfg, d, cf, quietLogger())
	eng.SetPublicIPv4Detector(&fakeIPv4Detector{ip: net.ParseIP("2.2.2.2")})

	res, err := eng.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	row := findRecord(res, cloudflare.RecordTypeA)
	if row == nil {
		t.Fatalf("no A record in %+v", res.Records)
	}
	if !row.Updated || row.OldIP != "1.1.1.1" || row.NewIP != "2.2.2.2" {
		t.Errorf("A row = %+v", row)
	}
	if row.Source != sourcePublicIPv4 {
		t.Errorf("A source = %q, want %q", row.Source, sourcePublicIPv4)
	}
	if cf.updated != "2.2.2.2" || cf.gotID != "a-1" {
		t.Errorf("updated=%q id=%q", cf.updated, cf.gotID)
	}
	if cf.gotType != cloudflare.RecordTypeA {
		t.Errorf("last GetRecord type = %q, want A", cf.gotType)
	}
	if !res.Updated {
		t.Error("Result.Updated should be true")
	}
}

func TestIPv4RecordCreated(t *testing.T) {
	cfg := ipv4Cfg()
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := &fakeCF{
		found:  true,
		record: cloudflare.Record{ID: "aaaa-1", Type: cloudflare.RecordTypeAAAA, Content: realGUA},
	}
	eng := NewEngine(cfg, d, cf, quietLogger())
	eng.SetPublicIPv4Detector(&fakeIPv4Detector{ip: net.ParseIP("2.2.2.2")})

	res, err := eng.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	row := findRecord(res, cloudflare.RecordTypeA)
	if row == nil || !row.Updated || row.Message != "A record created" {
		t.Fatalf("A row = %+v", row)
	}
	if cf.creCalls != 1 || cf.created != "2.2.2.2" || cf.createdType != cloudflare.RecordTypeA {
		t.Errorf("create calls=%d content=%q type=%q", cf.creCalls, cf.created, cf.createdType)
	}
}

func TestIPv4UnchangedIsQuiet(t *testing.T) {
	cfg := ipv4Cfg()
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := &fakeCF{
		found:   true,
		record:  cloudflare.Record{ID: "aaaa-1", Type: cloudflare.RecordTypeAAAA, Content: realGUA},
		foundA:  true,
		recordA: cloudflare.Record{ID: "a-1", Type: cloudflare.RecordTypeA, Content: "2.2.2.2"},
	}
	eng := NewEngine(cfg, d, cf, quietLogger())
	eng.SetPublicIPv4Detector(&fakeIPv4Detector{ip: net.ParseIP("2.2.2.2")})

	res, err := eng.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	row := findRecord(res, cloudflare.RecordTypeA)
	if row == nil || row.Updated || row.Message != "IPv4 unchanged, skipped" {
		t.Fatalf("A row = %+v", row)
	}
	if cf.updCalls != 0 || cf.creCalls != 0 {
		t.Errorf("unchanged A record should not be written: upd=%d cre=%d", cf.updCalls, cf.creCalls)
	}
	if res.Updated {
		t.Error("Result.Updated should be false")
	}
}

func TestIPv4DetectionFailureLeavesRecordAlone(t *testing.T) {
	cfg := ipv4Cfg()
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := &fakeCF{
		found:   true,
		record:  cloudflare.Record{ID: "aaaa-1", Type: cloudflare.RecordTypeAAAA, Content: realGUA},
		foundA:  true,
		recordA: cloudflare.Record{ID: "a-1", Type: cloudflare.RecordTypeA, Content: "2.2.2.2"},
	}
	eng := NewEngine(cfg, d, cf, quietLogger())
	eng.SetPublicIPv4Detector(&fakeIPv4Detector{err: errors.New("no route")})

	res, err := eng.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("detection failure must not fail the cycle: %v", err)
	}
	row := findRecord(res, cloudflare.RecordTypeA)
	if row == nil || row.Updated || row.Error != "" {
		t.Fatalf("A row = %+v", row)
	}
	if cf.updCalls != 0 || cf.creCalls != 0 {
		t.Errorf("A record must be untouched: upd=%d cre=%d", cf.updCalls, cf.creCalls)
	}
	if cf.getCalls != 1 {
		t.Errorf("GetRecord calls = %d, want only the AAAA lookup", cf.getCalls)
	}
}
