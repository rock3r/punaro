package canopiadapter

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// NewDeliveryClient creates the bounded HTTPS client used by durable adapter
// workers. caFile, when set, is an operator-selected PEM root bundle for a
// private collector CA; certificate validation is always retained.
func NewDeliveryClient(caFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	caFile = strings.TrimSpace(caFile)
	if caFile == "" {
		return &http.Client{Timeout: 750 * time.Millisecond, Transport: transport}, nil
	}
	if !filepath.IsAbs(caFile) {
		return nil, errors.New("Canopi TLS CA file must be an absolute path")
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read Canopi TLS CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("Canopi TLS CA file contains no PEM certificates")
	}
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}
	return &http.Client{Timeout: 750 * time.Millisecond, Transport: transport}, nil
}
