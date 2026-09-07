// Command mcp-androzoo serves AndroZoo over MCP: the latest.csv catalogue for
// selection, the HTTP API for retrieval.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-androzoo/internal/androzoo"
	"github.com/sebdraven/mcp-androzoo/internal/index"
	"github.com/sebdraven/mcp-androzoo/internal/mcptools"
	"github.com/sebdraven/mcp-androzoo/internal/service"
)

var version = "dev"

func main() {
	var (
		indexPath = flag.String("index", os.Getenv("ANDROZOO_INDEX"), "path to latest.csv or latest.csv.gz (env ANDROZOO_INDEX)")
		outDir    = flag.String("out", os.Getenv("ANDROZOO_OUT"), "default directory for downloaded APKs (env ANDROZOO_OUT)")
		lookup    = flag.String("lookup", "", "look up one hash in the catalogue and exit")
		pkg       = flag.String("pkg", "", "list the builds of one package and exit")
		limit     = flag.Int("limit", 100, "max results for the one-shot lookups")
		showVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	key, err := androzoo.Key()
	if err != nil {
		log.Fatalf("%v", err)
	}

	var ix *index.Index
	if strings.TrimSpace(*indexPath) != "" {
		ix, err = index.Open(*indexPath)
		if err != nil {
			log.Fatalf("%v", err)
		}
	} else {
		// Not fatal: az_gp_metadata and az_download work without it, and a
		// client that only ever downloads by hash needs no catalogue.
		log.Printf("no catalogue: -index unset, so az_lookup, az_search and az_versions will refuse. Get latest.csv from https://androzoo.uni.lu/lists")
	}

	svc := service.New(androzoo.New(key), ix, *outDir)
	ctx := context.Background()

	switch {
	case *lookup != "":
		res, err := svc.Lookup(ctx, []string{*lookup})
		exitWith(res, err)
	case *pkg != "":
		res, err := svc.Versions(ctx, *pkg, *limit)
		exitWith(res, err)
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "androzoo",
		Version: version,
	}, nil)
	mcptools.Register(server, svc)

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func exitWith(v any, err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatalf("encoding result: %v", err)
	}
	os.Exit(0)
}
