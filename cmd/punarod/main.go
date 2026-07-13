// punarod is the central Punaro relay daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rock3r/punaro/internal/config"
)

func main() {
	var envFile string
	flag.StringVar(&envFile, "env-file", "", "optional path to a dotenv file")
	flag.Parse()
	cfg, err := config.Load(envFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "punarod configuration error: %v\n", err)
		os.Exit(2)
	}
	if cfg.AttachmentsEnabled {
		fmt.Fprintln(os.Stderr, "punarod attachment v2 runtime is withheld: the required recipient-envelope, fresh-directory, revocation, and permit state machine is not implemented")
		os.Exit(2)
	}
	logger := log.New(os.Stderr, "punarod ", log.LstdFlags|log.LUTC)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}\n`)) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ready"}\n`)) })
	server := &http.Server{Addr: cfg.ListenAddr, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		logger.Printf("listening address=%s data_dir=%s log_level=%s", cfg.ListenAddr, cfg.DataDir, cfg.LogLevel)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("server stopped error=%v", err)
			os.Exit(1)
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		logger.Printf("graceful shutdown failed error=%v", err)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
