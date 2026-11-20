package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/service"
)

const (
	detectTimeout  = 100 * time.Second
	updateTimeout  = 120 * time.Second
	recordTimeout  = 20 * time.Second
	inboundTimeout = 150 * time.Second
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, s.svc.Status())
}

// configPayload is the editable subset of config.Config plus the OS-level
// autostart flag. Keeping it explicit prevents the console from writing fields
// it does not understand.
type configPayload struct {
	APIToken       string   `json:"api_token"`
	ZoneID         string   `json:"zone_id"`
	Domain         string   `json:"domain"`
	TTL            int      `json:"ttl"`
	Proxied        bool     `json:"proxied"`
	InterfaceName  string   `json:"interface_name"`
	Interval       string   `json:"interval"`
	Policy         string   `json:"policy"`
	Address        string   `json:"address"`
	ProbeTargets   []string `json:"probe_targets"`
	ProbeTimeout   string   `json:"probe_timeout"`
	ListenPort     int      `json:"listen_port"`
	AdminPort      int      `json:"admin_port"`
	InboundWorker  string   `json:"inbound_worker"`
	RequireInbound bool     `json:"require_inbound"`
	InboundPort    int      `json:"inbound_port"`
	ProbeBase      string   `json:"probe_base"`
	Autostart      bool     `json:"autostart"`
	ConfigPath     string   `json:"config_path,omitempty"`
}

func payloadFrom(cfg config.Config, autostart bool, path string) configPayload {
	return configPayload{
		APIToken:       cfg.APIToken,
		ZoneID:         cfg.ZoneID,
		Domain:         cfg.Domain,
		TTL:            cfg.TTL,
		Proxied:        cfg.Proxied,
		InterfaceName:  cfg.InterfaceName,
		Interval:       cfg.Interval,
		Policy:         string(cfg.Policy),
		Address:        cfg.Address,
		ProbeTargets:   cfg.ProbeTargetsToUse(),
		ProbeTimeout:   cfg.ProbeTimeout,
		ListenPort:     cfg.ListenPort,
		AdminPort:      cfg.AdminPort,
		InboundWorker:  cfg.InboundWorker,
		RequireInbound: cfg.RequireInbound,
		InboundPort:    cfg.InboundPort,
		ProbeBase:      cfg.ProbeBase,
		Autostart:      autostart,
		ConfigPath:     path,
	}
}

func (p configPayload) toConfig() config.Config {
	cfg := config.Default()
	cfg.APIToken = strings.TrimSpace(p.APIToken)
	cfg.ZoneID = strings.TrimSpace(p.ZoneID)
	cfg.Domain = strings.TrimSpace(p.Domain)
	cfg.TTL = p.TTL
	cfg.Proxied = p.Proxied
	cfg.InterfaceName = strings.TrimSpace(p.InterfaceName)
	cfg.Interval = strings.TrimSpace(p.Interval)
	cfg.Policy = config.TargetPolicy(strings.ToLower(strings.TrimSpace(p.Policy)))
	cfg.Address = strings.TrimSpace(p.Address)
	cfg.ProbeTargets = cleanList(p.ProbeTargets)
	cfg.ProbeTimeout = strings.TrimSpace(p.ProbeTimeout)
	cfg.ListenPort = p.ListenPort
	cfg.AdminPort = p.AdminPort
	cfg.InboundWorker = strings.TrimSpace(p.InboundWorker)
	cfg.RequireInbound = p.RequireInbound
	cfg.InboundPort = p.InboundPort
	cfg.ProbeBase = strings.TrimSpace(p.ProbeBase)
	if cfg.TTL == 0 {
		cfg.TTL = 1
	}
	if cfg.Interval == "" {
		cfg.Interval = config.Default().Interval
	}
	if cfg.ProbeTimeout == "" {
		cfg.ProbeTimeout = config.Default().ProbeTimeout
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = config.Default().ListenPort
	}
	if cfg.AdminPort == 0 {
		cfg.AdminPort = config.Default().AdminPort
	}
	return cfg
}

func cleanList(in []string) []string {
	var out []string
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, payloadFrom(s.svc.Config(), s.svc.AutostartEnabled(), s.svc.ConfigPath()))
	case http.MethodPut:
		var p configPayload
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			writeError(w, http.StatusBadRequest, "请求体不是有效的配置："+err.Error())
			return
		}
		cfg := p.toConfig()
		if err := s.svc.SaveConfig(cfg, p.Autostart); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, payloadFrom(s.svc.Config(), s.svc.AutostartEnabled(), s.svc.ConfigPath()))
	default:
		methodNotAllowed(w, "GET, PUT")
	}
}

func (s *Server) handleDetect(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	addrs, err := s.svc.Detect(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"addresses": addrs,
		"status":    s.svc.Status(),
	})
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), updateTimeout)
	defer cancel()
	ev, err := s.svc.Update(ctx)
	evErr := ""
	if err != nil {
		if errors.Is(err, service.ErrBusy) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		evErr = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"event": map[string]any{
			"updated":   ev.Result.Updated,
			"old_ip":    ev.Result.OldIP,
			"new_ip":    ev.Result.NewIP,
			"message":   ev.Result.Message,
			"time":      formatTime(ev.Result.Timestamp),
			"addresses": len(ev.Addrs),
			"error":     evErr,
		},
		"status": s.svc.Status(),
	})
}

func (s *Server) handleRecord(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), recordTimeout)
	defer cancel()
	rec, err := s.svc.Record(ctx)
	if err != nil {
		if errors.Is(err, cloudflare.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "Cloudflare 上没有找到这条 AAAA 记录")
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"record": rec})
}

func (s *Server) handleInboundCheck(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inboundTimeout)
	defer cancel()
	res, err := s.svc.InboundCheck(ctx)
	if err != nil {
		if errors.Is(err, service.ErrBusy) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result": res,
		"status": s.svc.Status(),
	})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	var after int64
	if raw := r.URL.Query().Get("after"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v < 0 {
			writeError(w, http.StatusBadRequest, "after 必须是非负整数")
			return
		}
		after = v
	}
	lines, next := s.svc.Logs(after)
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines, "next": next})
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	methodNotAllowed(w, method)
	return false
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
