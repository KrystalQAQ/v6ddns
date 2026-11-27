package ipv4

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func serve(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDetectUsesFirstUsableAnswer(t *testing.T) {
	first := serve(t, http.StatusOK, "192.168.1.2\n") // private: rejected
	second := serve(t, http.StatusOK, " 1.2.3.4 \n")
	d := NewDetectorWith([]string{first.URL, second.URL}, time.Second)
	ip, err := d.Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "1.2.3.4" {
		t.Errorf("ip = %s, want 1.2.3.4", got)
	}
}

func TestDetectSkipsBadResponses(t *testing.T) {
	notIP := serve(t, http.StatusOK, "<html>captive portal</html>")
	failing := serve(t, http.StatusInternalServerError, "")
	ok := serve(t, http.StatusOK, "8.8.4.4")
	d := NewDetectorWith([]string{notIP.URL, failing.URL, ok.URL}, time.Second)
	ip, err := d.Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "8.8.4.4" {
		t.Errorf("ip = %s, want 8.8.4.4", got)
	}
}

func TestDetectAllFail(t *testing.T) {
	a := serve(t, http.StatusOK, "10.0.0.1")
	b := serve(t, http.StatusOK, "not-an-ip")
	d := NewDetectorWith([]string{a.URL, b.URL}, time.Second)
	_, err := d.Detect(context.Background())
	if err == nil {
		t.Fatal("want error when every endpoint fails")
	}
	if !strings.Contains(err.Error(), a.URL) || !strings.Contains(err.Error(), b.URL) {
		t.Errorf("error should mention every failed endpoint: %v", err)
	}
}

func TestDetectHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("1.2.3.4"))
	}))
	defer srv.Close()
	d := NewDetectorWith([]string{srv.URL}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := d.Detect(ctx); err == nil {
		t.Fatal("want context error")
	}
}

func TestUsable(t *testing.T) {
	tests := map[string]bool{
		"1.2.3.4":      true,
		"223.5.5.5":    true,
		"10.1.2.3":     false,
		"127.0.0.1":    false,
		"169.254.1.1":  false,
		"100.64.0.1":   false,
		"192.0.2.10":   false,
		"198.18.0.1":   false,
		"203.0.113.10": false,
		"240.0.0.1":    false,
		"0.1.2.3":      false,
		"::1":          false,
		"2408:8262::1": false,
	}
	for raw, want := range tests {
		if got := Usable(net.ParseIP(raw)); got != want {
			t.Errorf("Usable(%s) = %v, want %v", raw, got, want)
		}
	}
}
