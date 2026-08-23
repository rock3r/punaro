// Command canopi runs the independently deployable Canopi lifecycle collector,
// state store, and deterministic 800x480 renderer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rock3r/punaro/internal/canopi"
	"github.com/rock3r/punaro/internal/canopicredential"
	"github.com/rock3r/punaro/internal/listener"
)

type serverConfig struct {
	listen             string
	allowLAN           bool
	tokenFile          string
	stateFile          string
	tlsCertFile        string
	tlsKeyFile         string
	grid               canopi.GridConfig
	workingTTL         time.Duration
	doneRetention      time.Duration
	maxLiveRecords     int
	maxFutureSkew      time.Duration
	relativeTimeBucket time.Duration
	title              string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	config, err := parseConfig(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "canopi configuration error: %v\n", err)
		return 2
	}
	token, err := loadToken(config.tokenFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "canopi configuration error: protected token is unavailable")
		return 2
	}
	store, err := canopi.OpenStore(config.stateFile, canopi.Config{
		WorkingTTL: config.workingTTL, DoneRetention: config.doneRetention,
		MaxLiveRecords: config.maxLiveRecords, MaxFutureSkew: config.maxFutureSkew,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "canopi state error: %v\n", err)
		return 1
	}
	handler, err := canopi.NewHandler(canopi.HandlerConfig{
		Store: store,
		Token: token,
		Render: canopi.RenderConfig{
			Width: 800, Height: 480, Grid: config.grid,
			RelativeTimeBucket: config.relativeTimeBucket,
			Title:              config.title,
		},
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "canopi configuration error: %v\n", err)
		return 2
	}
	networkListener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", config.listen)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "canopi listener error: %v\n", err)
		return 1
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	shutdownSignals := make(chan os.Signal, 1)
	signal.Notify(shutdownSignals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdownSignals
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	serve := server.Serve
	if config.tlsCertFile != "" {
		serve = func(listener net.Listener) error {
			return server.ServeTLS(listener, config.tlsCertFile, config.tlsKeyFile)
		}
	}
	if err := serve(networkListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		_, _ = fmt.Fprintf(stderr, "canopi server error: %v\n", err)
		return 1
	}
	return 0
}

func parseConfig(args []string) (serverConfig, error) {
	defaults := canopi.DefaultConfig()
	config := serverConfig{}
	flags := flag.NewFlagSet("canopi", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&config.listen, "listen", "127.0.0.1:8090", "concrete collector listener")
	flags.BoolVar(&config.allowLAN, "allow-lan", false, "explicitly allow a private LAN listener")
	flags.StringVar(&config.tokenFile, "token-file", "", "absolute private bearer-token file")
	flags.StringVar(&config.stateFile, "state-file", "./data/canopi-state.json", "durable state snapshot file")
	flags.StringVar(&config.tlsCertFile, "tls-cert-file", "", "absolute TLS certificate-chain file")
	flags.StringVar(&config.tlsKeyFile, "tls-key-file", "", "absolute TLS private-key file")
	flags.IntVar(&config.grid.Columns, "columns", 2, "panel grid columns")
	flags.IntVar(&config.grid.Rows, "rows", 6, "panel grid rows")
	flags.DurationVar(&config.workingTTL, "working-ttl", defaults.WorkingTTL, "non-terminal agent expiry")
	flags.DurationVar(&config.doneRetention, "done-retention", defaults.DoneRetention, "terminal agent retention")
	flags.IntVar(&config.maxLiveRecords, "max-live-records", defaults.MaxLiveRecords, "maximum current agent identities")
	flags.DurationVar(&config.maxFutureSkew, "max-future-skew", defaults.MaxFutureSkew, "maximum accepted future activity timestamp")
	flags.DurationVar(&config.relativeTimeBucket, "relative-time-bucket", time.Minute, "relative-time render bucket")
	flags.StringVar(&config.title, "title", "CANOPI", "provisional display title")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return serverConfig{}, errors.New("invalid command line")
	}
	endpoint, err := listener.Parse(config.listen)
	if err != nil || endpoint.Address.IsUnspecified() {
		return serverConfig{}, errors.New("listen must be a concrete non-wildcard IP and port")
	}
	if !endpoint.Address.IsLoopback() {
		if !config.allowLAN || (!endpoint.Address.IsPrivate() && !endpoint.Address.IsLinkLocalUnicast()) {
			return serverConfig{}, errors.New("non-loopback listeners require --allow-lan and a private or link-local IP")
		}
	}
	if !filepath.IsAbs(config.tokenFile) {
		return serverConfig{}, errors.New("token-file must be absolute")
	}
	if !filepath.IsAbs(config.stateFile) {
		absolute, err := filepath.Abs(config.stateFile)
		if err != nil {
			return serverConfig{}, errors.New("state-file is invalid")
		}
		config.stateFile = absolute
	}
	if (config.tlsCertFile == "") != (config.tlsKeyFile == "") {
		return serverConfig{}, errors.New("tls-cert-file and tls-key-file must be provided together")
	}
	for _, path := range []string{config.tlsCertFile, config.tlsKeyFile} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return serverConfig{}, errors.New("TLS file paths must be absolute and clean")
		}
	}
	if !endpoint.Address.IsLoopback() && config.tlsCertFile == "" {
		return serverConfig{}, errors.New("non-loopback listeners require TLS")
	}
	if err := config.grid.Validate(); err != nil {
		return serverConfig{}, err
	}
	if config.workingTTL <= 0 || config.doneRetention <= 0 || config.relativeTimeBucket <= 0 {
		return serverConfig{}, errors.New("TTL, retention, and render bucket must be positive")
	}
	if config.maxLiveRecords <= 0 || config.maxLiveRecords > 100_000 {
		return serverConfig{}, errors.New("max-live-records must be between 1 and 100000")
	}
	if config.maxFutureSkew <= 0 || config.maxFutureSkew > time.Hour {
		return serverConfig{}, errors.New("max-future-skew must be between zero and one hour")
	}
	if strings.TrimSpace(config.title) == "" {
		return serverConfig{}, errors.New("title is required")
	}
	return config, nil
}

func loadToken(path string) (string, error) {
	return canopicredential.ReadToken(path)
}
