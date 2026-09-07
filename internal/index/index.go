// Package index reads the AndroZoo latest.csv catalogue.
//
// AndroZoo has no search endpoint: selecting on package name, date, size or VT
// count is only possible against this file. It is scanned linearly on every
// query — no database is built — so results always reflect the file as it is
// on disk, and a stale catalogue is a fact about the file, not about AndroZoo.
package index

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Columns of latest.csv, in order.
const (
	colSHA256 = iota
	colSHA1
	colMD5
	colDexDate
	colAPKSize
	colPkgName
	colVerCode
	colVTDetection
	colVTScanDate
	colDexSize
	colMarkets
	numColumns
)

// Entry is one row of the catalogue. Hashes are kept whole and uppercase as
// AndroZoo writes them; VTDetection is -1 when the column is empty.
type Entry struct {
	SHA256      string   `json:"sha256"`
	SHA1        string   `json:"sha1"`
	MD5         string   `json:"md5"`
	DexDate     string   `json:"dex_date"`
	APKSize     int64    `json:"apk_size"`
	PkgName     string   `json:"pkg_name"`
	VerCode     int64    `json:"vercode"`
	VTDetection int      `json:"vt_detection"`
	VTScanDate  string   `json:"vt_scan_date"`
	DexSize     int64    `json:"dex_size"`
	Markets     []string `json:"markets"`
}

// Filter selects rows. Zero values mean "no constraint"; the criteria are
// ANDed. Hash matching is case-insensitive.
type Filter struct {
	SHA256   []string
	SHA1     []string
	MD5      []string
	PkgExact []string
	PkgMatch string
	PkgRegex string
	Market   string

	DexDateFrom string
	DexDateTo   string

	VTMin *int
	VTMax *int

	SizeMin int64
	SizeMax int64

	// Limit caps the rows returned. Without Random the scan stops as soon as
	// it is reached, which is why a package lookup is fast and an unfiltered
	// query is not.
	Limit int

	// Random draws a uniform sample of Limit rows among all matches. It forces
	// a full scan.
	Random bool
	Seed   uint64
}

// Stats describes the work a scan did, so a truncated answer is never mistaken
// for an exhaustive one.
type Stats struct {
	Scanned   int64         `json:"rows_scanned"`
	Matched   int64         `json:"rows_matched"`
	Returned  int           `json:"rows_returned"`
	Truncated bool          `json:"truncated"`
	Malformed int64         `json:"rows_malformed,omitempty"`
	Elapsed   time.Duration `json:"-"`
	ElapsedMS int64         `json:"elapsed_ms"`
}

type Index struct {
	path    string
	modTime time.Time
	size    int64
}

// Open checks the catalogue is readable and records its identity. Both
// latest.csv and latest.csv.gz are accepted.
func Open(path string) (*Index, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("index: no catalogue path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("index: %s is a directory", abs)
	}
	return &Index{path: abs, modTime: st.ModTime().UTC(), size: st.Size()}, nil
}

func (ix *Index) Path() string       { return ix.path }
func (ix *Index) ModTime() time.Time { return ix.modTime }
func (ix *Index) Size() int64        { return ix.size }

func (ix *Index) open() (io.ReadCloser, error) {
	f, err := os.Open(ix.path)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(ix.path, ".gz") {
		return f, nil
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("index: %s: %w", ix.path, err)
	}
	return gzipCloser{gz: gz, f: f}, nil
}

type gzipCloser struct {
	gz *gzip.Reader
	f  *os.File
}

func (g gzipCloser) Read(p []byte) (int, error) { return g.gz.Read(p) }
func (g gzipCloser) Close() error {
	err := g.gz.Close()
	if ferr := g.f.Close(); err == nil {
		err = ferr
	}
	return err
}

// Search scans the catalogue and returns the matching rows.
func (ix *Index) Search(ctx context.Context, f Filter) ([]Entry, Stats, error) {
	start := time.Now()
	m, err := compile(f)
	if err != nil {
		return nil, Stats{}, err
	}

	rc, err := ix.open()
	if err != nil {
		return nil, Stats{}, err
	}
	defer rc.Close()

	r := csv.NewReader(rc)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.ReuseRecord = true

	var (
		st   Stats
		out  []Entry
		rng  = rand.New(rand.NewPCG(f.Seed, 0x9E3779B97F4A7C15))
		lim  = f.Limit
		seen int64
	)
	if lim <= 0 {
		lim = 100
	}

	for {
		if st.Scanned%8192 == 0 {
			select {
			case <-ctx.Done():
				return out, ix.finish(&st, out, start), ctx.Err()
			default:
			}
		}
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			st.Malformed++
			if _, ok := err.(*csv.ParseError); ok {
				continue
			}
			return out, ix.finish(&st, out, start), fmt.Errorf("index: reading %s: %w", ix.path, err)
		}
		st.Scanned++
		if len(rec) < numColumns {
			st.Malformed++
			continue
		}
		if st.Scanned == 1 && strings.EqualFold(rec[colSHA256], "sha256") {
			continue
		}
		if !m.match(rec) {
			continue
		}
		st.Matched++

		if !f.Random {
			out = append(out, parse(rec))
			if len(out) >= lim {
				st.Truncated = true
				break
			}
			continue
		}

		// Reservoir sampling: uniform over all matches, one pass, bounded memory.
		if len(out) < lim {
			out = append(out, parse(rec))
		} else if j := rng.Int64N(seen + 1); j < int64(lim) {
			out[j] = parse(rec)
		}
		seen++
	}

	return out, ix.finish(&st, out, start), nil
}

func (ix *Index) finish(st *Stats, out []Entry, start time.Time) Stats {
	st.Returned = len(out)
	st.Elapsed = time.Since(start)
	st.ElapsedMS = st.Elapsed.Milliseconds()
	return *st
}

func parse(rec []string) Entry {
	e := Entry{
		SHA256:      strings.TrimSpace(rec[colSHA256]),
		SHA1:        strings.TrimSpace(rec[colSHA1]),
		MD5:         strings.TrimSpace(rec[colMD5]),
		DexDate:     strings.TrimSpace(rec[colDexDate]),
		PkgName:     strings.TrimSpace(rec[colPkgName]),
		VTScanDate:  strings.TrimSpace(rec[colVTScanDate]),
		VTDetection: -1,
	}
	e.APKSize, _ = strconv.ParseInt(strings.TrimSpace(rec[colAPKSize]), 10, 64)
	e.VerCode, _ = strconv.ParseInt(strings.TrimSpace(rec[colVerCode]), 10, 64)
	e.DexSize, _ = strconv.ParseInt(strings.TrimSpace(rec[colDexSize]), 10, 64)
	if v, err := strconv.Atoi(strings.TrimSpace(rec[colVTDetection])); err == nil {
		e.VTDetection = v
	}
	if mk := strings.TrimSpace(rec[colMarkets]); mk != "" {
		e.Markets = strings.Split(mk, "|")
	}
	return e
}

type matcher struct {
	sha256   map[string]struct{}
	sha1     map[string]struct{}
	md5      map[string]struct{}
	pkgExact map[string]struct{}
	pkgMatch string
	pkgRe    *regexp.Regexp
	market   string
	from, to string
	vtMin    *int
	vtMax    *int
	sizeMin  int64
	sizeMax  int64
}

func compile(f Filter) (*matcher, error) {
	m := &matcher{
		pkgMatch: strings.ToLower(strings.TrimSpace(f.PkgMatch)),
		market:   strings.ToLower(strings.TrimSpace(f.Market)),
		from:     strings.TrimSpace(f.DexDateFrom),
		to:       strings.TrimSpace(f.DexDateTo),
		vtMin:    f.VTMin,
		vtMax:    f.VTMax,
		sizeMin:  f.SizeMin,
		sizeMax:  f.SizeMax,
	}
	m.sha256 = hashSet(f.SHA256)
	m.sha1 = hashSet(f.SHA1)
	m.md5 = hashSet(f.MD5)
	if len(f.PkgExact) > 0 {
		m.pkgExact = make(map[string]struct{}, len(f.PkgExact))
		for _, p := range f.PkgExact {
			if p = strings.TrimSpace(p); p != "" {
				m.pkgExact[p] = struct{}{}
			}
		}
	}
	if re := strings.TrimSpace(f.PkgRegex); re != "" {
		c, err := regexp.Compile(re)
		if err != nil {
			return nil, fmt.Errorf("index: pkg_regex: %w", err)
		}
		m.pkgRe = c
	}
	return m, nil
}

func hashSet(hs []string) map[string]struct{} {
	if len(hs) == 0 {
		return nil
	}
	s := make(map[string]struct{}, len(hs))
	for _, h := range hs {
		if h = strings.ToUpper(strings.TrimSpace(h)); h != "" {
			s[h] = struct{}{}
		}
	}
	return s
}

func (m *matcher) hashHit(rec []string) bool {
	if m.sha256 != nil {
		if _, ok := m.sha256[strings.ToUpper(rec[colSHA256])]; ok {
			return true
		}
	}
	if m.sha1 != nil {
		if _, ok := m.sha1[strings.ToUpper(rec[colSHA1])]; ok {
			return true
		}
	}
	if m.md5 != nil {
		if _, ok := m.md5[strings.ToUpper(rec[colMD5])]; ok {
			return true
		}
	}
	return false
}

func (m *matcher) match(rec []string) bool {
	// Hashes are ORed across the three kinds: a lookup mixing the MD5 of one
	// sample and the SHA-256 of another must return both rows, not neither.
	if m.sha256 != nil || m.sha1 != nil || m.md5 != nil {
		if !m.hashHit(rec) {
			return false
		}
	}
	pkg := rec[colPkgName]
	if m.pkgExact != nil {
		if _, ok := m.pkgExact[pkg]; !ok {
			return false
		}
	}
	if m.pkgMatch != "" && !strings.Contains(strings.ToLower(pkg), m.pkgMatch) {
		return false
	}
	if m.pkgRe != nil && !m.pkgRe.MatchString(pkg) {
		return false
	}
	if m.market != "" && !strings.Contains(strings.ToLower(rec[colMarkets]), m.market) {
		return false
	}
	// dex_date is written as YYYY-MM-DD HH:MM:SS, so a lexical prefix
	// comparison is a date comparison.
	if m.from != "" && rec[colDexDate] < m.from {
		return false
	}
	if m.to != "" && rec[colDexDate] > m.to+"~" {
		return false
	}
	if m.vtMin != nil || m.vtMax != nil {
		v, err := strconv.Atoi(strings.TrimSpace(rec[colVTDetection]))
		if err != nil {
			return false
		}
		if m.vtMin != nil && v < *m.vtMin {
			return false
		}
		if m.vtMax != nil && v > *m.vtMax {
			return false
		}
	}
	if m.sizeMin > 0 || m.sizeMax > 0 {
		sz, err := strconv.ParseInt(strings.TrimSpace(rec[colAPKSize]), 10, 64)
		if err != nil {
			return false
		}
		if m.sizeMin > 0 && sz < m.sizeMin {
			return false
		}
		if m.sizeMax > 0 && sz > m.sizeMax {
			return false
		}
	}
	return true
}
