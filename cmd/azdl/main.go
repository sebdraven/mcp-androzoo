// Command azdl downloads APKs from AndroZoo in bulk: from a file of hashes, or
// straight from a catalogue query.
//
//	azdl -pkg-match cocospy -n 500 -manifest cocospy.csv -dry-run
//	azdl -i cocospy.csv -o ./apks -w 8
//	azdl -vt-max 0 -market play.google.com -n 500 -random -dry-run
//
// The catalogue is fetched on first use if it is not on disk.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/sebdraven/mcp-androzoo/internal/androzoo"
	"github.com/sebdraven/mcp-androzoo/internal/index"
	"github.com/sebdraven/mcp-androzoo/internal/service"
)

var version = "dev"

func main() {
	var (
		input     = flag.String("i", "", "file of SHA-256 hashes, one per line ('-' for stdin)")
		outDir    = flag.String("o", ".", "destination directory")
		workers   = flag.Int("w", 8, "concurrent downloads (capped at 20 by AndroZoo)")
		indexPath = flag.String("index", defaultIndexPath(), "catalogue file; downloaded here on first use if absent")
		refresh   = flag.Bool("refresh", false, "re-download the catalogue even if it is already on disk")
		pkgExact  = flag.String("pkg-exact", "", "select on an exact package name")
		pkgMatch  = flag.String("pkg-match", "", "select on a substring of the package name")
		pkgRegex  = flag.String("pkg-regex", "", "select on a regular expression over the package name")
		market    = flag.String("market", "", "select on a market, e.g. play.google.com")
		from      = flag.String("from", "", "earliest dex date, YYYY-MM-DD")
		to        = flag.String("to", "", "latest dex date, YYYY-MM-DD")
		vtMin     = flag.Int("vt-min", -1, "minimum VirusTotal detection count (-1 to not constrain)")
		vtMax     = flag.Int("vt-max", -1, "maximum VirusTotal detection count (-1 to not constrain)")
		n         = flag.Int("n", 100, "max samples to select from the catalogue")
		random    = flag.Bool("random", false, "draw a uniform sample among all matches instead of the first ones")
		seed      = flag.Uint64("seed", 0, "seed for -random, so a selection can be reproduced")
		manifest  = flag.String("manifest", "", "write the selected catalogue rows to this CSV")
		dryRun    = flag.Bool("dry-run", false, "select and write the manifest, download nothing")
		showVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	key, err := androzoo.Key()
	if err != nil && !*dryRun {
		log.Fatalf("%v", err)
	}
	client := androzoo.New(key)

	var (
		shas    []string
		entries []index.Entry
		svc     *service.Service
	)

	switch {
	case *input != "":
		shas, err = readHashes(*input)
		if err != nil {
			log.Fatalf("%v", err)
		}
		svc = service.New(client, nil, *outDir)

	default:
		ix, err := catalogue(ctx, client, *indexPath, *refresh)
		if err != nil {
			log.Fatalf("%v", err)
		}
		svc = service.New(client, ix, *outDir)

		f := index.Filter{
			PkgMatch:    *pkgMatch,
			PkgRegex:    *pkgRegex,
			Market:      *market,
			DexDateFrom: *from,
			DexDateTo:   *to,
			Limit:       *n,
			Random:      *random,
			Seed:        *seed,
		}
		if *vtMin >= 0 {
			f.VTMin = vtMin
		}
		if *vtMax >= 0 {
			f.VTMax = vtMax
		}
		if p := strings.TrimSpace(*pkgExact); p != "" {
			f.PkgExact = []string{p}
		}
		res, err := svc.Search(ctx, f)
		if err != nil {
			log.Fatalf("%v", err)
		}
		entries = res.Entries
		for _, e := range entries {
			shas = append(shas, e.SHA256)
		}
		log.Printf("%d rows scanned, %d matched, %d selected in %s",
			res.Stats.Scanned, res.Stats.Matched, res.Stats.Returned, res.Stats.Elapsed.Round(1e6))
		if res.Note != "" {
			log.Printf("note: %s", res.Note)
		}
	}

	if len(shas) == 0 {
		log.Fatalf("nothing selected")
	}
	if *manifest != "" {
		if err := writeManifest(*manifest, entries, shas); err != nil {
			log.Fatalf("%v", err)
		}
		log.Printf("manifest written to %s", *manifest)
	}
	if *dryRun {
		for _, s := range shas {
			fmt.Println(s)
		}
		return
	}

	res, err := svc.Download(ctx, shas, *outDir, *workers)
	for _, o := range res.Outcomes {
		if o.Status == "error" {
			log.Printf("%s: %s", o.SHA256, o.Error)
		}
	}
	log.Printf("%d requested, %d downloaded, %d already present, %d failed, into %s with %d workers",
		res.Requested, res.Succeeded, res.Skipped, res.Failed, res.Directory, res.Workers)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if res.Failed > 0 {
		os.Exit(1)
	}
}

// defaultIndexPath keeps the catalogue out of the working directory: it is
// nearly 3 GB and shared by every invocation.
func defaultIndexPath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "latest.csv.gz"
	}
	return filepath.Join(dir, "androzoo", "latest.csv.gz")
}

// catalogue opens the catalogue, downloading it first when it is missing. The
// download is resumable, so an interrupted first run costs nothing to retry.
func catalogue(ctx context.Context, c *androzoo.Client, path string, refresh bool) (*index.Index, error) {
	_, statErr := os.Stat(path)
	missing := errors.Is(statErr, fs.ErrNotExist)

	if missing || refresh {
		if refresh && !missing {
			if err := os.Remove(path); err != nil {
				return nil, err
			}
			log.Printf("refreshing the catalogue at %s", path)
		} else {
			log.Printf("no catalogue at %s — fetching it (about 2.7 GB, resumable)", path)
		}
		res, err := service.New(c, nil, "").FetchIndex(ctx, path)
		if err != nil {
			return nil, err
		}
		log.Printf("catalogue ready: %s, %d MB, server date %s", res.Path, res.Bytes/(1024*1024), res.LastModified)
	}
	return index.Open(path)
}

// readHashes accepts a bare list of hashes or the first column of a CSV, which
// is what a manifest looks like.
func readHashes(path string) ([]string, error) {
	var rc *os.File
	if path == "-" {
		rc = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		rc = f
	}

	var out []string
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, ",;\t "); i > 0 {
			line = line[:i]
		}
		line = strings.Trim(line, `"`)
		if strings.EqualFold(line, "sha256") {
			continue
		}
		if !androzoo.IsSHA256(line) {
			return nil, fmt.Errorf("%s: %q is not a SHA-256", path, line)
		}
		out = append(out, strings.ToUpper(line))
	}
	return out, sc.Err()
}

func writeManifest(path string, entries []index.Entry, shas []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if len(entries) == 0 {
		if err := w.Write([]string{"sha256"}); err != nil {
			return err
		}
		for _, s := range shas {
			if err := w.Write([]string{s}); err != nil {
				return err
			}
		}
		return w.Error()
	}

	if err := w.Write([]string{"sha256", "sha1", "md5", "dex_date", "apk_size", "pkg_name", "vercode", "vt_detection", "vt_scan_date", "dex_size", "markets"}); err != nil {
		return err
	}
	for _, e := range entries {
		row := []string{
			e.SHA256, e.SHA1, e.MD5, e.DexDate,
			strconv.FormatInt(e.APKSize, 10), e.PkgName,
			strconv.FormatInt(e.VerCode, 10), strconv.Itoa(e.VTDetection),
			e.VTScanDate, strconv.FormatInt(e.DexSize, 10),
			strings.Join(e.Markets, "|"),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return w.Error()
}
