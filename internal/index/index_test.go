package index

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha256Of(n int) string { return fmt.Sprintf("%064X", n) }
func sha1Of(n int) string   { return fmt.Sprintf("%040X", n) }
func md5Of(n int) string    { return fmt.Sprintf("%032X", n) }

// fixture mirrors latest.csv: a header, a quoted package name, an empty
// vt_detection, a pipe-separated markets column and a short row.
func fixture() string {
	rows := []string{
		"sha256,sha1,md5,dex_date,apk_size,pkg_name,vercode,vt_detection,vt_scan_date,dex_size,markets",
		fmt.Sprintf("%s,%s,%s,2019-05-01 10:00:00,3000000,com.duiyun.cocospy,11,12,2019-06-01 00:00:00,900000,play.google.com",
			sha256Of(1), sha1Of(1), md5Of(1)),
		fmt.Sprintf("%s,%s,%s,2021-03-02 09:00:00,4000000,com.sc.safespy.v2,163,5,2021-04-01 00:00:00,1100000,appchina|anzhi",
			sha256Of(2), sha1Of(2), md5Of(2)),
		fmt.Sprintf(`%s,%s,%s,2022-12-19 22:20:12,21912578,"com.life360.android.safetymapd",260640,0,2022-12-20 00:00:00,9417036,play.google.com`,
			sha256Of(3), sha1Of(3), md5Of(3)),
		fmt.Sprintf("%s,%s,%s,2015-01-01 00:00:00,100000,com.example.tool,1,,,50000,fdroid",
			sha256Of(4), sha1Of(4), md5Of(4)),
		fmt.Sprintf("%s,%s,%s,2020-07-07 07:07:07,3500000,com.duiyun.neatspy.v2,162,3,2020-08-01 00:00:00,950000,play.google.com",
			sha256Of(5), sha1Of(5), md5Of(5)),
		"short,row,only",
	}
	return strings.Join(rows, "\n") + "\n"
}

func writeFixture(t *testing.T, name string, gz bool) *Index {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if gz {
		w := gzip.NewWriter(f)
		if _, err := w.Write([]byte(fixture())); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	} else if _, err := f.WriteString(fixture()); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	ix, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func search(t *testing.T, ix *Index, f Filter) ([]Entry, Stats) {
	t.Helper()
	entries, st, err := ix.Search(context.Background(), f)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	return entries, st
}

func TestOpenRejectsMissingAndEmptyPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Error("empty path accepted")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "nope.csv")); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := Open(t.TempDir()); err == nil {
		t.Error("directory accepted")
	}
}

func TestHeaderSkippedAndMalformedCounted(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	entries, st := search(t, ix, Filter{})
	if len(entries) != 5 {
		t.Fatalf("got %d entries, want 5", len(entries))
	}
	for _, e := range entries {
		if strings.EqualFold(e.SHA256, "sha256") {
			t.Error("header row returned as an entry")
		}
	}
	if st.Malformed != 1 {
		t.Errorf("Malformed = %d, want 1", st.Malformed)
	}
}

func TestParsesFields(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	entries, _ := search(t, ix, Filter{SHA256: []string{sha256Of(3)}})
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.PkgName != "com.life360.android.safetymapd" {
		t.Errorf("PkgName = %q — quoting not handled", e.PkgName)
	}
	if e.APKSize != 21912578 {
		t.Errorf("APKSize = %d", e.APKSize)
	}
	if e.VerCode != 260640 {
		t.Errorf("VerCode = %d", e.VerCode)
	}
	if e.VTDetection != 0 {
		t.Errorf("VTDetection = %d, want 0", e.VTDetection)
	}
	if e.DexSize != 9417036 {
		t.Errorf("DexSize = %d", e.DexSize)
	}
	if len(e.Markets) != 1 || e.Markets[0] != "play.google.com" {
		t.Errorf("Markets = %v", e.Markets)
	}
}

func TestMissingVTDetectionIsMinusOne(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	entries, _ := search(t, ix, Filter{SHA256: []string{sha256Of(4)}})
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].VTDetection != -1 {
		t.Errorf("VTDetection = %d, want -1 for an empty column", entries[0].VTDetection)
	}
}

func TestPipeSeparatedMarkets(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	entries, _ := search(t, ix, Filter{SHA256: []string{sha256Of(2)}})
	if len(entries[0].Markets) != 2 {
		t.Fatalf("Markets = %v, want two entries", entries[0].Markets)
	}
}

func TestHashLookupIsCaseInsensitive(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	for _, h := range []string{sha256Of(1), strings.ToLower(sha256Of(1)), " " + sha256Of(1) + " "} {
		entries, _ := search(t, ix, Filter{SHA256: []string{h}})
		if len(entries) != 1 {
			t.Errorf("SHA256 %q matched %d rows, want 1", h, len(entries))
		}
	}
	entries, _ := search(t, ix, Filter{SHA1: []string{strings.ToLower(sha1Of(2))}})
	if len(entries) != 1 {
		t.Errorf("SHA1 lookup matched %d rows, want 1", len(entries))
	}
	entries, _ = search(t, ix, Filter{MD5: []string{md5Of(5)}})
	if len(entries) != 1 {
		t.Errorf("MD5 lookup matched %d rows, want 1", len(entries))
	}
}

func TestHashSetsAreORedAcrossKinds(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	entries, _ := search(t, ix, Filter{
		SHA256: []string{sha256Of(1)},
		MD5:    []string{md5Of(5)},
	})
	if len(entries) != 2 {
		t.Fatalf("got %d rows, want 2: hash kinds must be ORed, not ANDed", len(entries))
	}
}

func TestHashSetIsStillANDedWithOtherFilters(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	entries, _ := search(t, ix, Filter{
		SHA256:  []string{sha256Of(1), sha256Of(3)},
		Market:  "play.google.com",
		SizeMin: 10_000_000,
	})
	if len(entries) != 1 || entries[0].SHA256 != sha256Of(3) {
		t.Fatalf("got %d rows, want only the large one", len(entries))
	}
}

func TestPackageFilters(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)

	entries, _ := search(t, ix, Filter{PkgMatch: "DUIYUN"})
	if len(entries) != 2 {
		t.Errorf("PkgMatch matched %d rows, want 2 (case-insensitive substring)", len(entries))
	}

	entries, _ = search(t, ix, Filter{PkgRegex: `^com\.(sc|dy)\.`})
	if len(entries) != 1 {
		t.Errorf("PkgRegex matched %d rows, want 1", len(entries))
	}

	entries, _ = search(t, ix, Filter{PkgExact: []string{"com.duiyun.cocospy"}})
	if len(entries) != 1 {
		t.Errorf("PkgExact matched %d rows, want 1", len(entries))
	}

	entries, _ = search(t, ix, Filter{PkgExact: []string{"com.duiyun"}})
	if len(entries) != 0 {
		t.Errorf("PkgExact matched a prefix, want an exact match only")
	}
}

func TestBadRegexIsAnError(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	if _, _, err := ix.Search(context.Background(), Filter{PkgRegex: "("}); err == nil {
		t.Fatal("invalid regex accepted")
	}
}

func TestVTBoundsExcludeUnknown(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	zero := 0
	entries, _ := search(t, ix, Filter{VTMin: &zero, VTMax: &zero})
	if len(entries) != 1 || entries[0].SHA256 != sha256Of(3) {
		t.Fatalf("vt in [0,0] matched %d rows, want only the recorded zero", len(entries))
	}
	four := 4
	entries, _ = search(t, ix, Filter{VTMin: &four})
	if len(entries) != 2 {
		t.Errorf("vt >= 4 matched %d rows, want 2", len(entries))
	}
}

func TestDateRange(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)

	entries, _ := search(t, ix, Filter{DexDateFrom: "2020-01-01"})
	if len(entries) != 3 {
		t.Errorf("from 2020-01-01 matched %d rows, want 3", len(entries))
	}

	// A whole day is included by its date alone, times and all.
	entries, _ = search(t, ix, Filter{DexDateFrom: "2022-12-19", DexDateTo: "2022-12-19"})
	if len(entries) != 1 {
		t.Errorf("single-day range matched %d rows, want 1", len(entries))
	}

	entries, _ = search(t, ix, Filter{DexDateTo: "2016-01-01"})
	if len(entries) != 1 {
		t.Errorf("to 2016-01-01 matched %d rows, want 1", len(entries))
	}
}

func TestSizeAndMarket(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)

	entries, _ := search(t, ix, Filter{SizeMin: 3_400_000, SizeMax: 5_000_000})
	if len(entries) != 2 {
		t.Errorf("size range matched %d rows, want 2", len(entries))
	}

	entries, _ = search(t, ix, Filter{Market: "play.google.com"})
	if len(entries) != 3 {
		t.Errorf("market matched %d rows, want 3", len(entries))
	}

	entries, _ = search(t, ix, Filter{Market: "anzhi"})
	if len(entries) != 1 {
		t.Errorf("market inside a pipe list matched %d rows, want 1", len(entries))
	}
}

func TestLimitTruncates(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	entries, st := search(t, ix, Filter{Limit: 2})
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if !st.Truncated {
		t.Error("Truncated = false on a limited scan that stopped early")
	}
	if st.Returned != 2 {
		t.Errorf("Returned = %d, want 2", st.Returned)
	}
}

func TestRandomSamplesAllMatchesAndIsSeeded(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)

	entries, st := search(t, ix, Filter{Limit: 2, Random: true, Seed: 7})
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if st.Matched != 5 {
		t.Errorf("Matched = %d, want 5: a random draw must see every match", st.Matched)
	}
	if st.Truncated {
		t.Error("Truncated = true on a random draw, which scans the whole file")
	}

	again, _ := search(t, ix, Filter{Limit: 2, Random: true, Seed: 7})
	for i := range entries {
		if entries[i].SHA256 != again[i].SHA256 {
			t.Fatalf("same seed gave a different draw: %s vs %s", entries[i].SHA256, again[i].SHA256)
		}
	}
}

func TestGzipCatalogue(t *testing.T) {
	ix := writeFixture(t, "latest.csv.gz", true)
	entries, st := search(t, ix, Filter{})
	if len(entries) != 5 {
		t.Fatalf("got %d entries from the gzipped catalogue, want 5", len(entries))
	}
	if st.Scanned == 0 {
		t.Error("Scanned = 0")
	}
}

func TestCancelledContextStops(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ix.Search(ctx, Filter{}); err == nil {
		t.Fatal("a cancelled scan returned no error")
	}
}

func TestCatalogueIdentity(t *testing.T) {
	ix := writeFixture(t, "latest.csv", false)
	if !strings.HasSuffix(ix.Path(), "latest.csv") {
		t.Errorf("Path = %q", ix.Path())
	}
	if ix.Size() == 0 {
		t.Error("Size = 0")
	}
	if ix.ModTime().IsZero() {
		t.Error("ModTime is zero")
	}
}
