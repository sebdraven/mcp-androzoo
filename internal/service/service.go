// Package service joins the two halves of AndroZoo: the catalogue on disk,
// which answers "which samples exist and what do we know about them", and the
// live API, which answers "give me this APK" and "what did Google Play say".
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sebdraven/mcp-androzoo/internal/androzoo"
	"github.com/sebdraven/mcp-androzoo/internal/index"
)

type Service struct {
	client *androzoo.Client
	idx    *index.Index
	outDir string
}

func New(c *androzoo.Client, ix *index.Index, outDir string) *Service {
	return &Service{client: c, idx: ix, outDir: outDir}
}

// ErrNoIndex is returned by every catalogue-backed call when no latest.csv was
// configured. It is a configuration fact, not an empty result.
var ErrNoIndex = errors.New("no AndroZoo catalogue configured: point -index at latest.csv (or latest.csv.gz), downloaded from https://androzoo.uni.lu/lists")

// Catalogue identifies the file an answer came from. Two queries a month apart
// against different catalogue files are not comparable, so this travels with
// every result.
type Catalogue struct {
	Path     string `json:"path"`
	Modified string `json:"modified"`
	SizeMB   int64  `json:"size_mb"`
}

type SearchResult struct {
	Catalogue Catalogue     `json:"catalogue"`
	Stats     index.Stats   `json:"stats"`
	Entries   []index.Entry `json:"entries"`
	Note      string        `json:"note,omitempty"`
}

type GPResult struct {
	Package   string            `json:"package"`
	VerCode   *int64            `json:"vercode,omitempty"`
	FetchedAt string            `json:"fetched_at"`
	Records   []json.RawMessage `json:"records"`
}

type DownloadOutcome struct {
	SHA256 string `json:"sha256"`
	Path   string `json:"path,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
	Status string `json:"status"` // downloaded | skipped | error
	Error  string `json:"error,omitempty"`
}

type DownloadResult struct {
	Directory string            `json:"directory"`
	Requested int               `json:"requested"`
	Succeeded int               `json:"succeeded"`
	Skipped   int               `json:"skipped"`
	Failed    int               `json:"failed"`
	Workers   int               `json:"workers"`
	Outcomes  []DownloadOutcome `json:"outcomes"`
}

// FetchResult describes a catalogue download.
type FetchResult struct {
	Path         string `json:"path"`
	Bytes        int64  `json:"bytes_written"`
	TotalSize    int64  `json:"total_size"`
	Resumed      bool   `json:"resumed"`
	LastModified string `json:"server_last_modified,omitempty"`
	Note         string `json:"note,omitempty"`
}

// FetchIndex downloads the nightly catalogue to dest, resuming a previous
// attempt when the server allows it. The transfer lands in dest+".part" and is
// renamed only once complete, so an interrupted download never leaves a
// half-written catalogue that would silently answer queries with a fraction of
// the corpus.
//
// The file is upwards of 2.7 GB compressed and is rebuilt nightly, so a resumed
// transfer can straddle two builds; the server refusing the range is how that
// gets caught.
func (s *Service) FetchIndex(ctx context.Context, dest string) (FetchResult, error) {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return FetchResult{}, fmt.Errorf("no destination path for the catalogue")
	}
	if st, err := os.Stat(dest); err == nil && st.IsDir() {
		dest = filepath.Join(dest, "latest.csv.gz")
	}
	if dir := filepath.Dir(dest); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return FetchResult{}, err
		}
	}

	part := dest + ".part"
	var offset int64
	if st, err := os.Stat(part); err == nil {
		offset = st.Size()
	}
	requested := offset

	body, info, err := s.client.IndexReader(ctx, offset)
	if err != nil {
		return FetchResult{}, err
	}
	defer body.Close()

	flags := os.O_CREATE | os.O_WRONLY
	if info.Resumed {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
		offset = 0
	}
	f, err := os.OpenFile(part, flags, 0o644)
	if err != nil {
		return FetchResult{}, err
	}

	n, copyErr := io.Copy(f, body)
	closeErr := f.Close()
	if copyErr != nil {
		return FetchResult{Path: part, Bytes: n, Resumed: info.Resumed},
			fmt.Errorf("catalogue download interrupted after %d bytes (kept at %s, run again to resume): %w", n, part, copyErr)
	}
	if closeErr != nil {
		return FetchResult{Path: part, Bytes: n}, closeErr
	}

	if err := verifyGzip(part, dest); err != nil {
		return FetchResult{Path: part, Bytes: n}, err
	}
	if err := os.Rename(part, dest); err != nil {
		return FetchResult{Path: part, Bytes: n}, err
	}

	res := FetchResult{
		Path:         dest,
		Bytes:        offset + n,
		TotalSize:    info.TotalSize,
		Resumed:      info.Resumed,
		LastModified: info.LastModified,
	}
	if requested > 0 && !info.Resumed {
		res.Note = "the server would not resume, so the file was downloaded from the start"
	}
	return res, nil
}

// verifyGzip checks the magic bytes rather than the size: a truncated transfer
// and an HTML error page both produce a file, and only one of them is a
// catalogue.
func verifyGzip(part, dest string) error {
	if !strings.HasSuffix(dest, ".gz") {
		return nil
	}
	f, err := os.Open(part)
	if err != nil {
		return err
	}
	defer f.Close()
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("downloaded catalogue is too short to be gzip: %w", err)
	}
	if magic[0] != 0x1f || magic[1] != 0x8b {
		return fmt.Errorf("downloaded catalogue is not gzip (starts with %#x %#x): the server most likely returned an error page, and %s was kept for inspection", magic[0], magic[1], part)
	}
	return nil
}

func (s *Service) catalogue() Catalogue {
	return Catalogue{
		Path:     s.idx.Path(),
		Modified: s.idx.ModTime().Format(time.RFC3339),
		SizeMB:   s.idx.Size() / (1024 * 1024),
	}
}

// Search runs a filtered scan of the catalogue.
func (s *Service) Search(ctx context.Context, f index.Filter) (SearchResult, error) {
	if s.idx == nil {
		return SearchResult{}, ErrNoIndex
	}
	entries, stats, err := s.idx.Search(ctx, f)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return SearchResult{}, err
	}
	res := SearchResult{Catalogue: s.catalogue(), Stats: stats, Entries: entries}
	if err != nil {
		res.Note = "scan interrupted before the end of the catalogue: these results are partial"
	} else if stats.Truncated {
		res.Note = "limit reached before the end of the catalogue: more rows match than are shown, and they are the first ones in file order, not the most relevant"
	}
	return res, nil
}

// Lookup finds the catalogue rows for hashes of any of the three kinds.
func (s *Service) Lookup(ctx context.Context, hashes []string) (SearchResult, error) {
	if s.idx == nil {
		return SearchResult{}, ErrNoIndex
	}
	var f index.Filter
	for _, h := range hashes {
		h = strings.TrimSpace(h)
		switch len(h) {
		case 64:
			f.SHA256 = append(f.SHA256, h)
		case 40:
			f.SHA1 = append(f.SHA1, h)
		case 32:
			f.MD5 = append(f.MD5, h)
		case 0:
		default:
			return SearchResult{}, fmt.Errorf("%q is not an MD5, SHA-1 or SHA-256", h)
		}
	}
	if len(f.SHA256)+len(f.SHA1)+len(f.MD5) == 0 {
		return SearchResult{}, fmt.Errorf("no hash given")
	}
	// A hash set is only matched by whole rows, so the limit is the set size.
	f.Limit = len(f.SHA256) + len(f.SHA1) + len(f.MD5)
	res, err := s.Search(ctx, f)
	if err != nil {
		return res, err
	}
	// Truncation here means every hash was found, not that rows were dropped.
	res.Stats.Truncated = false
	res.Note = ""
	if res.Stats.Returned < f.Limit {
		res.Note = "some hashes are absent from this catalogue; AndroZoo may still hold them if the file is older than the sample"
	}
	return res, nil
}

// Versions returns every build of one package, oldest version code first.
func (s *Service) Versions(ctx context.Context, pkg string, limit int) (SearchResult, error) {
	if strings.TrimSpace(pkg) == "" {
		return SearchResult{}, fmt.Errorf("package name is required")
	}
	if limit <= 0 {
		limit = 500
	}
	res, err := s.Search(ctx, index.Filter{PkgExact: []string{pkg}, Limit: limit})
	if err != nil {
		return res, err
	}
	sort.SliceStable(res.Entries, func(i, j int) bool {
		if res.Entries[i].VerCode != res.Entries[j].VerCode {
			return res.Entries[i].VerCode < res.Entries[j].VerCode
		}
		return res.Entries[i].DexDate < res.Entries[j].DexDate
	})
	return res, nil
}

// GPMetadata returns the Google Play records AndroZoo holds for a package, for
// one version code or for all of them.
func (s *Service) GPMetadata(ctx context.Context, pkg string, verCode *int64) (GPResult, error) {
	out := GPResult{
		Package:   strings.TrimSpace(pkg),
		VerCode:   verCode,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if verCode != nil {
		rec, err := s.client.GPMetadataVersion(ctx, pkg, *verCode)
		if err != nil {
			return GPResult{}, err
		}
		out.Records = []json.RawMessage{rec}
		return out, nil
	}
	recs, err := s.client.GPMetadata(ctx, pkg)
	if err != nil {
		return GPResult{}, err
	}
	out.Records = recs
	return out, nil
}

// Download fetches APKs into dir, one file per SHA-256. Existing files are left
// alone; each download lands in a temporary file, is checked against its hash
// and only then takes its final name, so an interrupted run never leaves a
// truncated APK behind under a valid name.
func (s *Service) Download(ctx context.Context, shas []string, dir string, workers int) (DownloadResult, error) {
	if dir = strings.TrimSpace(dir); dir == "" {
		dir = s.outDir
	}
	if dir == "" {
		return DownloadResult{}, fmt.Errorf("no output directory: pass one, or start the server with -out")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return DownloadResult{}, err
	}

	clean := make([]string, 0, len(shas))
	for _, h := range shas {
		h = strings.ToUpper(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if !androzoo.IsSHA256(h) {
			return DownloadResult{}, fmt.Errorf("%q is not a SHA-256: AndroZoo downloads by SHA-256 only", h)
		}
		clean = append(clean, h)
	}
	if len(clean) == 0 {
		return DownloadResult{}, fmt.Errorf("no SHA-256 given")
	}

	if workers <= 0 {
		workers = 8
	}
	workers = min(workers, androzoo.MaxConcurrentDownloads, len(clean))

	res := DownloadResult{Directory: dir, Requested: len(clean), Workers: workers}
	outcomes := make([]DownloadOutcome, len(clean))

	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				outcomes[i] = s.fetchOne(ctx, clean[i], dir)
			}
		}()
	}
	for i := range clean {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return res, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()

	for _, o := range outcomes {
		switch o.Status {
		case "downloaded":
			res.Succeeded++
		case "skipped":
			res.Skipped++
		default:
			res.Failed++
		}
	}
	res.Outcomes = outcomes
	return res, nil
}

func (s *Service) fetchOne(ctx context.Context, sha, dir string) DownloadOutcome {
	final := filepath.Join(dir, sha+".apk")
	if st, err := os.Stat(final); err == nil && st.Size() > 0 {
		return DownloadOutcome{SHA256: sha, Path: final, Bytes: st.Size(), Status: "skipped"}
	}

	tmp, err := os.CreateTemp(dir, "."+sha+".part-*")
	if err != nil {
		return DownloadOutcome{SHA256: sha, Status: "error", Error: err.Error()}
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	h := sha256.New()
	n, err := s.client.Download(ctx, sha, io.MultiWriter(tmp, h))
	closeErr := tmp.Close()
	if err != nil {
		return DownloadOutcome{SHA256: sha, Status: "error", Error: err.Error()}
	}
	if closeErr != nil {
		return DownloadOutcome{SHA256: sha, Status: "error", Error: closeErr.Error()}
	}

	if got := strings.ToUpper(hex.EncodeToString(h.Sum(nil))); got != sha {
		return DownloadOutcome{
			SHA256: sha,
			Status: "error",
			Error:  fmt.Sprintf("content hashes to %s, not to the requested %s", got, sha),
		}
	}
	if err := os.Rename(tmpName, final); err != nil {
		return DownloadOutcome{SHA256: sha, Status: "error", Error: err.Error()}
	}
	return DownloadOutcome{SHA256: sha, Path: final, Bytes: n, Status: "downloaded"}
}
