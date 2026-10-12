// uac-psiphon: Psiphon inner-hop helper for UAC Spoofer Desktop (engine 3).
//
// Same role as the mobile `:uacpow` process (libgopsi.so): it runs the
// Psiphon tunnel core with the exact same config keys the Android app uses
// (PowPsiphonProtocols.buildConfig) and exposes a local SOCKS proxy. Traffic
// reaches it through the aether outer leg via UpstreamProxyURL, exactly like
// mobile chains Psiphon over WARP.
//
// Usage:
//   uac-psiphon -config psiphon.json -serverList server_entries.txt [-meekOnly]
//
// Machine-readable progress goes to stdout, one `PSIPHON <json>` line per
// notice, so the Python coordinator can drive the connect-steps card.

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// Hex markers of the "cloudflare" and "fastly" fronting hosts inside the
// hex-encoded server entries. Mirrors the mobile meek-front filter:
// Akamai fronts reset on the carrier, Cloudflare/Fastly TLS still completes.
const (
	cloudflareHex = "636c6f7564666c617265"
	fastlyHex     = "666173746c79"
)

type prefixedWriter struct {
	target io.Writer
}

func (w *prefixedWriter) Write(data []byte) (int, error) {
	text := strings.TrimRight(string(data), "\r\n")
	if text == "" {
		return len(data), nil
	}
	for _, line := range strings.Split(text, "\n") {
		fmt.Fprintf(w.target, "PSIPHON %s\n", strings.TrimSpace(line))
	}
	return len(data), nil
}

func filterMeekEntries(path string) (string, error) {
	entries, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer entries.Close()

	filtered, err := os.CreateTemp("", "uac-psiphon-entries-*.txt")
	if err != nil {
		return "", err
	}
	defer filtered.Close()

	scanner := bufio.NewScanner(entries)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	kept := 0
	wrote := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.Contains(lower, cloudflareHex) && !strings.Contains(lower, fastlyHex) {
			continue
		}
		if wrote {
			fmt.Fprintln(filtered, "")
		}
		fmt.Fprint(filtered, line)
		wrote = true
		kept++
	}
	if err := scanner.Err(); err != nil {
		os.Remove(filtered.Name())
		return "", err
	}
	if kept == 0 {
		os.Remove(filtered.Name())
		return "", fmt.Errorf("meek filter kept no entries")
	}
	fmt.Fprintf(os.Stderr, "PSIPHON filtered server entries to cloudflare/fastly: %d kept\n", kept)
	return filtered.Name(), nil
}

func main() {
	var configFilename string
	flag.StringVar(&configFilename, "config", "", "Psiphon config JSON file (same keys as mobile buildConfig)")
	var entriesFilename string
	flag.StringVar(&entriesFilename, "serverList", "", "hex-encoded server entries file")
	var meekOnly bool
	flag.BoolVar(&meekOnly, "meekOnly", false, "keep only cloudflare/fastly fronted entries (direct meek mode)")
	flag.Parse()

	psiphon.SetNoticeWriter(&prefixedWriter{target: os.Stdout})

	if configFilename == "" {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("configuration file is required")
		os.Exit(1)
	}
	configFileContents, err := os.ReadFile(configFilename)
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("error loading configuration file: %s", err)
		os.Exit(1)
	}
	config, err := psiphon.LoadConfig(configFileContents)
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("error processing configuration file: %s", err)
		os.Exit(1)
	}

	if meekOnly && entriesFilename != "" {
		filtered, err := filterMeekEntries(entriesFilename)
		if err != nil {
			psiphon.NoticeError("error filtering server entries: %s", err)
			os.Exit(1)
		}
		defer os.Remove(filtered)
		entriesFilename = filtered
	}

	if err := config.Commit(true); err != nil {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("error committing configuration: %s", err)
		os.Exit(1)
	}

	// The datastore must be open before embedded server entries can be
	// imported — same order as the reference ConsoleClient.
	if err := psiphon.OpenDataStore(config); err != nil {
		psiphon.NoticeError("error opening datastore: %s", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		fmt.Fprintln(os.Stderr, "PSIPHON stopping on signal")
		cancel()
	}()

	if entriesFilename != "" {
		if err := psiphon.ImportEmbeddedServerEntries(ctx, config, entriesFilename, ""); err != nil {
			psiphon.NoticeError("error importing server entries: %s", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "PSIPHON server entries imported: %d\n", psiphon.CountServerEntries())
	}

	controller, err := psiphon.NewController(config)
	if err != nil {
		psiphon.NoticeError("error creating controller: %s", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stdout, "PSIPHON {\"noticeType\":\"HelperStart\"}")
	controller.Run(ctx)
	psiphon.CloseDataStore()
	fmt.Fprintln(os.Stdout, "PSIPHON {\"noticeType\":\"HelperExit\"}")
}
