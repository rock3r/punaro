package canopiadapter

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewDeliveryClientTrustsConfiguredPEMRoot(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	certificate := server.Certificate()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	caPath := filepath.Join(t.TempDir(), "collector-ca.pem")
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := NewDeliveryClient(caPath)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request with configured CA: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
}

func TestNewDeliveryClientRejectsInvalidPEM(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "collector-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDeliveryClient(caPath); err == nil {
		t.Fatal("NewDeliveryClient accepted invalid PEM")
	}
}

func TestNewDeliveryClientRejectsRelativeCAPath(t *testing.T) {
	if _, err := NewDeliveryClient("collector-ca.pem"); err == nil {
		t.Fatal("NewDeliveryClient accepted a relative CA path")
	}
}
