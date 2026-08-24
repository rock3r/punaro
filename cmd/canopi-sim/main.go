// Command canopi-sim emits realistic, privacy-safe multi-machine lifecycle
// activity against a Canopi collector.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"github.com/rock3r/punaro/internal/canopi/simulator"
	"github.com/rock3r/punaro/internal/canopicredential"
	"github.com/rock3r/punaro/internal/canopitransport"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("canopi-sim", flag.ContinueOnError)
	flags.SetOutput(stderr)
	endpoint := flags.String("endpoint", "http://127.0.0.1:8090", "Canopi collector origin")
	tokenFile := flags.String("token-file", "", "private bearer-token file")
	interval := flags.Duration("interval", 8*time.Second, "event batch interval")
	once := flags.Bool("once", false, "send one batch and exit")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *tokenFile == "" || *interval <= 0 {
		return 2
	}
	parsedEndpoint, err := url.Parse(*endpoint)
	if err != nil || parsedEndpoint.Host == "" || canopitransport.ValidateOrigin(*endpoint) != nil {
		return 2
	}
	token, err := canopicredential.ReadToken(*tokenFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "canopi-sim: protected token is unavailable")
		return 1
	}
	runID, err := newRunID()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "canopi-sim: run identity unavailable")
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runSimulation(ctx, client, *endpoint, token, runID, *interval, *once, stderr); err != nil {
		return 1
	}
	return 0
}

func newRunID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func runSimulation(ctx context.Context, client *http.Client, endpoint, token, runID string, interval time.Duration, once bool, stderr io.Writer) error {
	tick := 0
	pending := simulator.Events(time.Now().UTC(), tick, runID)
	for {
		remaining, err := postBatch(client, endpoint, token, pending)
		switch {
		case err != nil:
			_, _ = fmt.Fprintln(stderr, "canopi-sim: collector unavailable")
			if once {
				return err
			}
		case len(remaining) != 0:
			pending = remaining
			_, _ = fmt.Fprintln(stderr, "canopi-sim: collector rejected events; retrying")
			if once {
				return errors.New("collector rejected simulator events")
			}
		default:
			if once {
				return nil
			}
			tick++
			pending = nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
			if pending == nil {
				pending = simulator.Events(time.Now().UTC(), tick, runID)
			}
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		}
	}
}

func postBatch(client *http.Client, endpoint, token string, events []protocol.Event) ([]protocol.Event, error) {
	if client == nil {
		return nil, errors.New("HTTP client is required")
	}
	payload, err := json.Marshal(events)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, strings.TrimRight(endpoint, "/")+"/v1/events:batch", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := canopitransport.DoWithoutRedirects(client, request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("collector returned HTTP %d", response.StatusCode)
	}
	if response.StatusCode != http.StatusMultiStatus {
		return nil, nil
	}
	const maxBatchResponseBytes = 64 << 10
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBatchResponseBytes+1))
	if err != nil || len(body) > maxBatchResponseBytes {
		return nil, errors.New("collector returned an invalid batch response")
	}
	var result struct {
		Results []struct {
			Status int `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.Results) != len(events) {
		return nil, errors.New("collector returned an invalid batch response")
	}
	remaining := make([]protocol.Event, 0)
	for index, item := range result.Results {
		if item.Status < 100 || item.Status > 599 {
			return nil, errors.New("collector returned an invalid batch status")
		}
		if item.Status < 200 || item.Status >= 300 {
			remaining = append(remaining, events[index])
		}
	}
	return remaining, nil
}
