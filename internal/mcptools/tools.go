// Package mcptools exposes the service over MCP.
//
// The tool descriptions state two things a model gets wrong otherwise: that
// the catalogue is a file frozen at the day it was downloaded, so absence is
// never evidence AndroZoo lacks a sample, and that no filtering endpoint
// exists upstream — every selection is a linear scan whose cost is the size of
// that file.
package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-androzoo/internal/index"
	"github.com/sebdraven/mcp-androzoo/internal/service"
)

type registry struct{ svc *service.Service }

func Register(s *mcp.Server, svc *service.Service) {
	r := &registry{svc: svc}

	mcp.AddTool(s, &mcp.Tool{
		Name: "az_lookup",
		Description: "Look up one or more APKs in the AndroZoo catalogue by MD5, SHA-1 or SHA-256. " +
			"Returns package name, version code, dex date, sizes, the VirusTotal detection count recorded at scan time and the markets the APK was seen on. " +
			"The VT count is a snapshot taken when AndroZoo scanned the sample, not a current verdict. " +
			"A hash that is absent means it is not in this catalogue file — which may simply be older than the sample.",
	}, r.lookup)

	mcp.AddTool(s, &mcp.Tool{
		Name: "az_search",
		Description: "Select APKs from the AndroZoo catalogue on package name, dex date, APK size, VirusTotal detection count or market. " +
			"This is the only way to search AndroZoo: the API downloads by SHA-256 and nothing else. " +
			"Every call scans the whole catalogue file linearly, so narrow filters and small limits are cheap and open-ended ones are not. " +
			"Set random to draw a uniform sample among all matches rather than the first ones in file order — that is what you want for building a control set.",
	}, r.search)

	mcp.AddTool(s, &mcp.Tool{
		Name: "az_versions",
		Description: "List every build of one package present in the catalogue, oldest version code first. " +
			"This is the diachronic view the Play Store cannot give, which only ever serves the current version. " +
			"Takes an exact package name; use az_search when you only have a fragment.",
	}, r.versions)

	mcp.AddTool(s, &mcp.Tool{
		Name: "az_gp_metadata",
		Description: "Fetch the Google Play metadata AndroZoo holds for a package: title, developer, category, ratings, install counts, as harvested. " +
			"This one queries the live AndroZoo API, not the catalogue file. " +
			"Records were collected at times that do not follow the release order, and a record may exist for a version whose APK AndroZoo does not hold.",
	}, r.gpMetadata)

	mcp.AddTool(s, &mcp.Tool{
		Name: "az_fetch_index",
		Description: "Download the AndroZoo catalogue (latest.csv.gz) to a path on this machine — the prerequisite for az_lookup, az_search and az_versions. " +
			"The file is over 2.7 GB compressed and rebuilt nightly, so this takes minutes and may outlast an MCP client's timeout; an interrupted run resumes where it stopped when called again. " +
			"The server must be restarted with -index pointing at the result before the catalogue tools will see it.",
	}, r.fetchIndex)

	mcp.AddTool(s, &mcp.Tool{
		Name: "az_download",
		Description: "Download APKs by SHA-256 into a directory on this machine. " +
			"Each file is verified against its hash before it takes its final name, and hashes already present are skipped. " +
			"AndroZoo asks for at most 20 concurrent downloads and that ceiling is enforced here. " +
			"APKs are live malware as often as not: they land on disk, they are never opened.",
	}, r.download)
}

type lookupInput struct {
	Hashes []string `json:"hashes" jsonschema:"MD5, SHA-1 or SHA-256 hashes, whole and untruncated"`
}

type searchInput struct {
	PkgMatch    string `json:"pkg_match,omitempty" jsonschema:"case-insensitive substring of the package name"`
	PkgRegex    string `json:"pkg_regex,omitempty" jsonschema:"RE2 regular expression on the package name"`
	PkgExact    string `json:"pkg_exact,omitempty" jsonschema:"exact package name"`
	Market      string `json:"market,omitempty" jsonschema:"market the APK was seen on, e.g. play.google.com, appchina, anzhi"`
	DexDateFrom string `json:"dex_date_from,omitempty" jsonschema:"earliest dex date, YYYY-MM-DD"`
	DexDateTo   string `json:"dex_date_to,omitempty" jsonschema:"latest dex date, YYYY-MM-DD"`
	VTMin       *int   `json:"vt_min,omitempty" jsonschema:"minimum VirusTotal detection count"`
	VTMax       *int   `json:"vt_max,omitempty" jsonschema:"maximum VirusTotal detection count; 0 with vt_min 0 selects samples clean at scan time"`
	SizeMin     int64  `json:"apk_size_min,omitempty" jsonschema:"minimum APK size in bytes"`
	SizeMax     int64  `json:"apk_size_max,omitempty" jsonschema:"maximum APK size in bytes"`
	Limit       int    `json:"limit,omitempty" jsonschema:"max rows to return (default 100)"`
	Random      bool   `json:"random,omitempty" jsonschema:"draw a uniform sample among all matches instead of the first ones; forces a full scan"`
	Seed        uint64 `json:"seed,omitempty" jsonschema:"seed for random sampling, so a selection can be reproduced"`
}

type versionsInput struct {
	Package string `json:"package" jsonschema:"exact package name, e.g. com.duiyun.cocospy"`
	Limit   int    `json:"limit,omitempty" jsonschema:"max builds to return (default 500)"`
}

type gpInput struct {
	Package string `json:"package" jsonschema:"exact package name"`
	VerCode *int64 `json:"vercode,omitempty" jsonschema:"one version code; omit for every record on the package"`
}

type fetchIndexInput struct {
	Path string `json:"path" jsonschema:"where to write the catalogue; a directory gets latest.csv.gz inside it"`
}

type downloadInput struct {
	SHA256    []string `json:"sha256" jsonschema:"SHA-256 hashes to download, whole and untruncated"`
	Directory string   `json:"directory,omitempty" jsonschema:"destination directory (default: the server's -out)"`
	Workers   int      `json:"workers,omitempty" jsonschema:"concurrent downloads, capped at 20 (default 8)"`
}

func (r *registry) lookup(ctx context.Context, _ *mcp.CallToolRequest, in lookupInput) (*mcp.CallToolResult, service.SearchResult, error) {
	if len(in.Hashes) == 0 {
		return nil, service.SearchResult{}, fmt.Errorf("hashes is required")
	}
	res, err := r.svc.Lookup(ctx, in.Hashes)
	return nil, res, err
}

func (r *registry) search(ctx context.Context, _ *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, service.SearchResult, error) {
	f := index.Filter{
		PkgMatch:    in.PkgMatch,
		PkgRegex:    in.PkgRegex,
		Market:      in.Market,
		DexDateFrom: in.DexDateFrom,
		DexDateTo:   in.DexDateTo,
		VTMin:       in.VTMin,
		VTMax:       in.VTMax,
		SizeMin:     in.SizeMin,
		SizeMax:     in.SizeMax,
		Limit:       in.Limit,
		Random:      in.Random,
		Seed:        in.Seed,
	}
	if p := strings.TrimSpace(in.PkgExact); p != "" {
		f.PkgExact = []string{p}
	}
	res, err := r.svc.Search(ctx, f)
	return nil, res, err
}

func (r *registry) versions(ctx context.Context, _ *mcp.CallToolRequest, in versionsInput) (*mcp.CallToolResult, service.SearchResult, error) {
	res, err := r.svc.Versions(ctx, in.Package, in.Limit)
	return nil, res, err
}

func (r *registry) gpMetadata(ctx context.Context, _ *mcp.CallToolRequest, in gpInput) (*mcp.CallToolResult, service.GPResult, error) {
	if strings.TrimSpace(in.Package) == "" {
		return nil, service.GPResult{}, fmt.Errorf("package is required")
	}
	res, err := r.svc.GPMetadata(ctx, in.Package, in.VerCode)
	return nil, res, err
}

func (r *registry) fetchIndex(ctx context.Context, _ *mcp.CallToolRequest, in fetchIndexInput) (*mcp.CallToolResult, service.FetchResult, error) {
	if strings.TrimSpace(in.Path) == "" {
		return nil, service.FetchResult{}, fmt.Errorf("path is required")
	}
	res, err := r.svc.FetchIndex(ctx, in.Path)
	return nil, res, err
}

func (r *registry) download(ctx context.Context, _ *mcp.CallToolRequest, in downloadInput) (*mcp.CallToolResult, service.DownloadResult, error) {
	if len(in.SHA256) == 0 {
		return nil, service.DownloadResult{}, fmt.Errorf("sha256 is required")
	}
	res, err := r.svc.Download(ctx, in.SHA256, in.Directory, in.Workers)
	return nil, res, err
}
