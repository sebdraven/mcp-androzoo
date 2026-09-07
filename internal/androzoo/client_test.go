package androzoo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSHA = "003D7A6BFA6FB9A4A6224CBCF4615D08EF20E76024E7412346584A072FD5A376"

func TestDownloadStreamsBody(t *testing.T) {
	payload := []byte("PK\x03\x04 not really an apk")

	var gotKey, gotSHA, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.URL.Query().Get("apikey")
		gotSHA = r.URL.Query().Get("sha256")
		w.Write(payload)
	}))
	defer srv.Close()

	c := New("KEY", WithBaseURL(srv.URL))
	var buf bytes.Buffer
	n, err := c.Download(context.Background(), testSHA, &buf)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if n != int64(len(payload)) {
		t.Errorf("wrote %d bytes, want %d", n, len(payload))
	}
	if !bytes.Equal(buf.Bytes(), payload) {
		t.Errorf("body = %q, want %q", buf.Bytes(), payload)
	}
	if gotPath != "/api/download" {
		t.Errorf("path = %q, want /api/download", gotPath)
	}
	if gotKey != "KEY" {
		t.Errorf("apikey = %q", gotKey)
	}
	if gotSHA != testSHA {
		t.Errorf("sha256 = %q, want %q", gotSHA, testSHA)
	}
}

func TestDownloadRejectsNonSHA256(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server was called for an invalid hash")
	}))
	defer srv.Close()

	c := New("KEY", WithBaseURL(srv.URL))
	for _, bad := range []string{"", "deadbeef", strings.Repeat("z", 64), "003D7A6B…"} {
		if _, err := c.Download(context.Background(), bad, &bytes.Buffer{}); err == nil {
			t.Errorf("Download(%q) accepted an invalid hash", bad)
		}
	}
}

func TestDownloadWithoutKey(t *testing.T) {
	c := New("")
	if _, err := c.Download(context.Background(), testSHA, &bytes.Buffer{}); err == nil {
		t.Fatal("Download with no key succeeded")
	}
}

func TestAPIErrorCarriesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid api key", http.StatusForbidden)
	}))
	defer srv.Close()

	c := New("BAD", WithBaseURL(srv.URL))
	_, err := c.Download(context.Background(), testSHA, &bytes.Buffer{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v (%T), want *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Error(), "API key") {
		t.Errorf("message does not mention the key: %s", apiErr)
	}
}

func TestGPMetadataAllVersions(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"pkg":"com.example","versionCode":1},{"pkg":"com.example","versionCode":2}]`))
	}))
	defer srv.Close()

	c := New("KEY", WithBaseURL(srv.URL))
	recs, err := c.GPMetadata(context.Background(), "com.example")
	if err != nil {
		t.Fatalf("GPMetadata: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if gotPath != "/api/get_gp_metadata/com.example" {
		t.Errorf("path = %q", gotPath)
	}
	var first map[string]any
	if err := json.Unmarshal(recs[0], &first); err != nil {
		t.Fatalf("record is not JSON: %v", err)
	}
	if first["pkg"] != "com.example" {
		t.Errorf("first record = %v", first)
	}
}

func TestGPMetadataOneVersion(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`{"pkg":"com.example","versionCode":65}`))
	}))
	defer srv.Close()

	c := New("KEY", WithBaseURL(srv.URL))
	rec, err := c.GPMetadataVersion(context.Background(), "occam.hammer.drone", 65)
	if err != nil {
		t.Fatalf("GPMetadataVersion: %v", err)
	}
	if gotPath != "/api/get_gp_metadata/occam.hammer.drone/65" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(string(rec), "versionCode") {
		t.Errorf("record = %s", rec)
	}
}

func TestGPMetadataRejectsEmptyPackage(t *testing.T) {
	c := New("KEY")
	if _, err := c.GPMetadata(context.Background(), "   "); err == nil {
		t.Fatal("empty package accepted")
	}
}

func TestIsSHA256(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{testSHA, true},
		{strings.ToLower(testSHA), true},
		{" " + testSHA + " ", true},
		{testSHA[:63], false},
		{testSHA + "A", false},
		{"", false},
		{strings.Repeat("g", 64), false},
		{"003D7A6BFA6FB9A4A6224CBCF461", false},
	}
	for _, c := range cases {
		if got := IsSHA256(c.in); got != c.want {
			t.Errorf("IsSHA256(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
