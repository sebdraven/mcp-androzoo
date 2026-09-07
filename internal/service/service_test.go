package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sebdraven/mcp-androzoo/internal/androzoo"
	"github.com/sebdraven/mcp-androzoo/internal/index"
)

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

var (
	apkA = []byte("PK\x03\x04 sample A")
	apkB = []byte("PK\x03\x04 sample B")
)

// stub serves APKs by SHA-256. A hash mapped to different bytes is how a
// corrupted or substituted download is simulated.
func stub(t *testing.T, bodies map[string][]byte) *androzoo.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/download" {
			body, ok := bodies[strings.ToUpper(r.URL.Query().Get("sha256"))]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Write(body)
			return
		}
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return androzoo.New("KEY", androzoo.WithBaseURL(srv.URL))
}

func catalogue(t *testing.T, rows ...string) *index.Index {
	t.Helper()
	header := "sha256,sha1,md5,dex_date,apk_size,pkg_name,vercode,vt_detection,vt_scan_date,dex_size,markets"
	path := filepath.Join(t.TempDir(), "latest.csv")
	body := header + "\n" + strings.Join(rows, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ix, err := index.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

// row derives the SHA-1 and MD5 columns from the SHA-256 so every fixture row
// carries three distinct, row-specific hashes.
func row(sha, pkg string, vercode int, dexDate string) string {
	sha1 := sha[:40]
	md5 := sha[:32]
	return fmt.Sprintf("%s,%s,%s,%s,1000000,%s,%d,0,2024-01-01 00:00:00,500000,play.google.com",
		sha, sha1, md5, dexDate, pkg, vercode)
}

func TestCatalogueToolsRefuseWithoutIndex(t *testing.T) {
	svc := New(stub(t, nil), nil, t.TempDir())
	ctx := context.Background()

	if _, err := svc.Search(ctx, index.Filter{}); !errors.Is(err, ErrNoIndex) {
		t.Errorf("Search error = %v, want ErrNoIndex", err)
	}
	if _, err := svc.Lookup(ctx, []string{hashOf(apkA)}); !errors.Is(err, ErrNoIndex) {
		t.Errorf("Lookup error = %v, want ErrNoIndex", err)
	}
	if _, err := svc.Versions(ctx, "com.example", 0); !errors.Is(err, ErrNoIndex) {
		t.Errorf("Versions error = %v, want ErrNoIndex", err)
	}
}

func TestLookupMixesHashKinds(t *testing.T) {
	shaA, shaB := hashOf(apkA), hashOf(apkB)
	ix := catalogue(t,
		row(shaA, "com.example.one", 1, "2020-01-01 00:00:00"),
		row(shaB, "com.example.two", 2, "2021-01-01 00:00:00"),
	)
	svc := New(stub(t, nil), ix, t.TempDir())

	// A SHA-256 of one sample and the MD5 of another: both rows, not neither.
	res, err := svc.Lookup(context.Background(), []string{shaA, shaB[:32]})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Stats.Returned != 2 {
		t.Fatalf("Returned = %d, want 2", res.Stats.Returned)
	}
	if res.Note != "" {
		t.Errorf("Note = %q on a complete lookup", res.Note)
	}
	if res.Catalogue.Path != ix.Path() {
		t.Error("result does not carry the catalogue it came from")
	}
}

func TestLookupBySHA1(t *testing.T) {
	shaA := hashOf(apkA)
	ix := catalogue(t, row(shaA, "com.example.one", 1, "2020-01-01 00:00:00"))
	svc := New(stub(t, nil), ix, t.TempDir())

	res, err := svc.Lookup(context.Background(), []string{shaA[:40]})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Stats.Returned != 1 {
		t.Fatalf("Returned = %d, want 1", res.Stats.Returned)
	}
}

func TestLookupRejectsMalformedHash(t *testing.T) {
	ix := catalogue(t, row(hashOf(apkA), "com.example.one", 1, "2020-01-01 00:00:00"))
	svc := New(stub(t, nil), ix, t.TempDir())

	if _, err := svc.Lookup(context.Background(), []string{"deadbeef"}); err == nil {
		t.Error("a hash of no recognised length was accepted")
	}
	if _, err := svc.Lookup(context.Background(), nil); err == nil {
		t.Error("an empty hash list was accepted")
	}
}

func TestLookupFlagsMissingHashes(t *testing.T) {
	shaA := hashOf(apkA)
	ix := catalogue(t, row(shaA, "com.example.one", 1, "2020-01-01 00:00:00"))
	svc := New(stub(t, nil), ix, t.TempDir())

	res, err := svc.Lookup(context.Background(), []string{shaA, hashOf(apkB)})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Note == "" {
		t.Error("a partial hit carried no note about the absent hash")
	}
	if res.Stats.Truncated {
		t.Error("Truncated = true on a complete hash lookup")
	}
}

func TestVersionsSortedByVerCode(t *testing.T) {
	ix := catalogue(t,
		row(fmt.Sprintf("%064X", 3), "com.duiyun.cocospy", 30, "2022-01-01 00:00:00"),
		row(fmt.Sprintf("%064X", 1), "com.duiyun.cocospy", 10, "2020-01-01 00:00:00"),
		row(fmt.Sprintf("%064X", 9), "com.other.app", 1, "2021-01-01 00:00:00"),
		row(fmt.Sprintf("%064X", 2), "com.duiyun.cocospy", 20, "2021-01-01 00:00:00"),
	)
	svc := New(stub(t, nil), ix, t.TempDir())

	res, err := svc.Versions(context.Background(), "com.duiyun.cocospy", 0)
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(res.Entries) != 3 {
		t.Fatalf("got %d builds, want 3", len(res.Entries))
	}
	for i, want := range []int64{10, 20, 30} {
		if res.Entries[i].VerCode != want {
			t.Errorf("entry %d has vercode %d, want %d", i, res.Entries[i].VerCode, want)
		}
	}
}

func TestVersionsRejectsEmptyPackage(t *testing.T) {
	svc := New(stub(t, nil), catalogue(t), t.TempDir())
	if _, err := svc.Versions(context.Background(), "  ", 0); err == nil {
		t.Error("empty package name accepted")
	}
}

func TestDownloadWritesVerifiedFile(t *testing.T) {
	shaA := hashOf(apkA)
	dir := t.TempDir()
	svc := New(stub(t, map[string][]byte{shaA: apkA}), nil, dir)

	res, err := svc.Download(context.Background(), []string{shaA}, "", 4)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Succeeded != 1 || res.Failed != 0 {
		t.Fatalf("%d succeeded, %d failed", res.Succeeded, res.Failed)
	}
	got, err := os.ReadFile(filepath.Join(dir, shaA+".apk"))
	if err != nil {
		t.Fatalf("reading the downloaded file: %v", err)
	}
	if string(got) != string(apkA) {
		t.Errorf("file content = %q", got)
	}
}

func TestDownloadRejectsHashMismatch(t *testing.T) {
	shaA := hashOf(apkA)
	dir := t.TempDir()
	// The server answers the request for A with B's bytes.
	svc := New(stub(t, map[string][]byte{shaA: apkB}), nil, dir)

	res, err := svc.Download(context.Background(), []string{shaA}, "", 1)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Failed != 1 {
		t.Fatalf("%d failed, want 1", res.Failed)
	}
	if !strings.Contains(res.Outcomes[0].Error, "hashes to") {
		t.Errorf("error = %q, want a hash mismatch", res.Outcomes[0].Error)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a rejected download left %d files behind: %v", len(entries), entries)
	}
}

func TestDownloadSkipsExisting(t *testing.T) {
	shaA := hashOf(apkA)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, shaA+".apk"), apkA, 0o644); err != nil {
		t.Fatal(err)
	}
	// No body registered: any HTTP call would 404 and be reported as an error.
	svc := New(stub(t, nil), nil, dir)

	res, err := svc.Download(context.Background(), []string{shaA}, "", 1)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Skipped != 1 || res.Failed != 0 {
		t.Fatalf("%d skipped, %d failed, want 1 skipped", res.Skipped, res.Failed)
	}
}

func TestDownloadReportsMissingSample(t *testing.T) {
	dir := t.TempDir()
	svc := New(stub(t, nil), nil, dir)

	res, err := svc.Download(context.Background(), []string{hashOf(apkB)}, "", 1)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Failed != 1 {
		t.Fatalf("%d failed, want 1", res.Failed)
	}
	if !strings.Contains(res.Outcomes[0].Error, "404") && !strings.Contains(res.Outcomes[0].Error, "not found") {
		t.Errorf("error = %q, want a 404", res.Outcomes[0].Error)
	}
}

func TestDownloadCapsWorkers(t *testing.T) {
	shas := make([]string, 0, 30)
	bodies := map[string][]byte{}
	for i := range 30 {
		b := fmt.Appendf(nil, "PK\x03\x04 sample %d", i)
		h := hashOf(b)
		shas = append(shas, h)
		bodies[h] = b
	}
	dir := t.TempDir()
	svc := New(stub(t, bodies), nil, dir)

	res, err := svc.Download(context.Background(), shas, "", 100)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Workers > androzoo.MaxConcurrentDownloads {
		t.Errorf("Workers = %d, above the ceiling AndroZoo asks for (%d)", res.Workers, androzoo.MaxConcurrentDownloads)
	}
	if res.Succeeded != len(shas) {
		t.Errorf("%d succeeded, want %d", res.Succeeded, len(shas))
	}
}

func TestDownloadRejectsNonSHA256AndEmpty(t *testing.T) {
	svc := New(stub(t, nil), nil, t.TempDir())
	if _, err := svc.Download(context.Background(), []string{"deadbeef"}, "", 1); err == nil {
		t.Error("a non-SHA-256 was accepted")
	}
	if _, err := svc.Download(context.Background(), nil, "", 1); err == nil {
		t.Error("an empty hash list was accepted")
	}
}

func TestDownloadNeedsADirectory(t *testing.T) {
	svc := New(stub(t, nil), nil, "")
	if _, err := svc.Download(context.Background(), []string{hashOf(apkA)}, "", 1); err == nil {
		t.Error("a download with no directory anywhere was accepted")
	}
}

func TestGPMetadataCarriesFetchTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"pkg":"com.example"}]`))
	}))
	defer srv.Close()

	svc := New(androzoo.New("KEY", androzoo.WithBaseURL(srv.URL)), nil, t.TempDir())
	res, err := svc.GPMetadata(context.Background(), "com.example", nil)
	if err != nil {
		t.Fatalf("GPMetadata: %v", err)
	}
	if res.FetchedAt == "" {
		t.Error("FetchedAt is empty: a live answer must carry when it was taken")
	}
	if len(res.Records) != 1 {
		t.Errorf("got %d records, want 1", len(res.Records))
	}
}
