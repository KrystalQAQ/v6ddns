package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "cf-secret-token-1234567890"

func TestGetRecord(t *testing.T) {
	want := Record{
		ID:      "rec-1",
		Type:    RecordTypeAAAA,
		Name:    "home.example.com",
		Content: "2408:8262:c7f:6c4f:2a:85cb:1452:5d19",
		TTL:     1,
		Proxied: false,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q, want Bearer token", got)
		}
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		q := r.URL.Query()
		if q.Get("type") != RecordTypeAAAA || q.Get("name") != want.Name {
			t.Errorf("query = %v, want type=AAAA name=%s", q, want.Name)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"errors":  []any{},
			"result":  []Record{want},
		})
	}))
	defer srv.Close()

	c := NewClientWithBaseURL(testToken, srv.URL, time.Second)
	got, err := c.GetRecord(context.Background(), "zone-1", want.Name)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if got != want {
		t.Errorf("record = %+v, want %+v", got, want)
	}
}

func TestGetRecordNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"errors":  []any{},
			"result":  []Record{},
		})
	}))
	defer srv.Close()

	c := NewClientWithBaseURL(testToken, srv.URL, time.Second)
	_, err := c.GetRecord(context.Background(), "zone-1", "missing.example.com")
	if !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("err = %v, want ErrRecordNotFound", err)
	}
}

func TestUpdateRecord(t *testing.T) {
	var gotBody recordPatch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("method = %s, want PATCH", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/zones/zone-1/dns_records/rec-1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{}})
	}))
	defer srv.Close()

	c := NewClientWithBaseURL(testToken, srv.URL, time.Second)
	err := c.UpdateRecord(context.Background(), "zone-1", "rec-1", "2408::1", 300, true)
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
	want := recordPatch{Content: "2408::1", TTL: 300, Proxied: true}
	if gotBody != want {
		t.Errorf("body = %+v, want %+v", gotBody, want)
	}
}

func TestCreateRecord(t *testing.T) {
	var gotBody recordCreate
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/zones/zone-1/dns_records") {
			t.Errorf("path = %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{}})
	}))
	defer srv.Close()

	c := NewClientWithBaseURL(testToken, srv.URL, time.Second)
	err := c.CreateRecord(context.Background(), "zone-1", "home.example.com", "2408::2", 1, false)
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	want := recordCreate{Type: RecordTypeAAAA, Name: "home.example.com", Content: "2408::2", TTL: 1, Proxied: false}
	if gotBody != want {
		t.Errorf("body = %+v, want %+v", gotBody, want)
	}
}

func TestAPIErrorIncludesStatusAndDetailsButNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"errors": []map[string]any{
				{"code": 9109, "message": "Invalid access token " + testToken},
				{"code": 7003, "message": "Missing zone"},
			},
		})
	}))
	defer srv.Close()

	c := NewClientWithBaseURL(testToken, srv.URL, time.Second)
	_, err := c.GetRecord(context.Background(), "zone-1", "home.example.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err type = %T (%v), want *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", apiErr.StatusCode)
	}
	if len(apiErr.Details) != 2 || apiErr.Details[0].Code != 9109 {
		t.Errorf("details = %+v", apiErr.Details)
	}
	msg := err.Error()
	if strings.Contains(msg, testToken) {
		t.Errorf("error leaked token: %q", msg)
	}
	if !strings.Contains(msg, "403") || !strings.Contains(msg, "9109") || !strings.Contains(msg, "7003") {
		t.Errorf("error missing status/codes: %q", msg)
	}
	if !strings.Contains(msg, "***") {
		t.Errorf("token was not redacted: %q", msg)
	}
}

func TestSuccessFalseWithHTTP200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"errors":  []map[string]any{{"code": 1000, "message": "denied"}},
			"result":  []Record{},
		})
	}))
	defer srv.Close()

	c := NewClientWithBaseURL(testToken, srv.URL, time.Second)
	_, err := c.GetRecord(context.Background(), "zone-1", "home.example.com")
	if err == nil {
		t.Fatal("want error for success=false response")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
}

func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []Record{}})
	}))
	defer srv.Close()

	c := NewClientWithBaseURL(testToken, srv.URL, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.GetRecord(ctx, "zone-1", "home.example.com")
	if err == nil {
		t.Fatal("want error on cancelled context")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error leaked token: %q", err.Error())
	}
}

func TestClientTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()

	c := NewClientWithBaseURL(testToken, srv.URL, 20*time.Millisecond)
	start := time.Now()
	_, err := c.GetRecord(context.Background(), "zone-1", "home.example.com")
	if err == nil {
		t.Fatal("want timeout error")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("timeout took %v, expected prompt failure", elapsed)
	}
}
