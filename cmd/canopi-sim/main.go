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
	if err != nil || (parsedEndpoint.Scheme != "http" && parsedEndpoint.Scheme != "https") || parsedEndpoint.Host == "" || parsedEndpoint.Path != "" {
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
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	for tick := 0; ; tick++ {
		if err := postBatch(client, *endpoint, token, simulator.Events(time.Now().UTC(), tick, runID)); err != nil {
			_, _ = fmt.Fprintln(stderr, "canopi-sim: collector unavailable")
			if *once {
				return 1
			}
		}
		if *once {
			return 0
		}
		timer := time.NewTimer(*interval)
		select {
		case <-timer.C:
		case <-stop:
			if !timer.Stop() {
				<-timer.C
			}
			return 0
		}
	}
}

func newRunID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func postBatch(client *http.Client, endpoint, token string, events []protocol.Event) error {
	if client == nil {
		return errors.New("HTTP client is required")
	}
	payload, err := json.Marshal(events)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, strings.TrimRight(endpoint, "/")+"/v1/events:batch", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("collector returned HTTP %d", response.StatusCode)
	}
	return nil
}
