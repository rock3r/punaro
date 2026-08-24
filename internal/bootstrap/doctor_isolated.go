package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
)

const (
	maximumDoctorHelperRequest = 128 << 10
	maximumDoctorHelperOutput  = 128 << 10
)

type doctorHelperRequest struct {
	Directory        string                       `json:"directory"`
	MachineID        string                       `json:"machine_id,omitempty"`
	Origin           string                       `json:"origin,omitempty"`
	Keys             map[string]ed25519.PublicKey `json:"keys,omitempty"`
	KeysFile         string                       `json:"keys_file,omitempty"`
	GOOS             string                       `json:"goos,omitempty"`
	GOARCH           string                       `json:"goarch,omitempty"`
	Now              time.Time                    `json:"now,omitempty"`
	BootstrapRelease string                       `json:"bootstrap_release,omitempty"`
}

type doctorHelperOutput struct {
	buffer   strings.Builder
	maximum  int
	overflow bool
}

func (output *doctorHelperOutput) Write(value []byte) (int, error) {
	remaining := output.maximum - output.buffer.Len()
	if remaining > 0 {
		retained := value
		if len(retained) > remaining {
			retained = retained[:remaining]
		}
		_, _ = output.buffer.Write(retained)
	}
	if len(value) > remaining {
		output.overflow = true
	}
	return len(value), nil
}

var doctorHelperExecutable = os.Executable

func encodeDoctorHelperRequest(request DoctorRequest) (string, bool) {
	if request.HTTP != nil || request.FreeBytes != nil {
		return "", false
	}
	payload := doctorHelperRequest{
		Directory: request.Directory, MachineID: request.MachineID, Origin: request.Origin, Keys: request.Keys, KeysFile: request.KeysFile,
		GOOS: request.GOOS, GOARCH: request.GOARCH, Now: request.Now, BootstrapRelease: request.BootstrapRelease,
	}
	body, err := json.Marshal(payload)
	if err != nil || len(body) == 0 || len(body) > maximumDoctorHelperRequest {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(body), true
}

// IsolatedDoctor runs the complete bootstrap diagnostic in a bounded child so
// synchronous filesystem operations cannot outlive the caller's deadline.
func IsolatedDoctor(ctx context.Context, request DoctorRequest) (punarodiagnostic.Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	encoded, ok := encodeDoctorHelperRequest(request)
	if !ok {
		return punarodiagnostic.Report{}, errors.New("bootstrap doctor helper request is invalid")
	}
	executable, err := doctorHelperExecutable()
	if err != nil {
		return punarodiagnostic.Report{}, errors.New("bootstrap doctor helper is unavailable")
	}
	command := exec.CommandContext(ctx, executable, "doctor-bootstrap-report", "--request", encoded) // #nosec G204 -- current signed executable and a bounded encoded request.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := doctorHelperOutput{maximum: maximumDoctorHelperOutput}
	command.Stdout = &output
	if err := command.Run(); err != nil || ctx.Err() != nil || output.overflow {
		return punarodiagnostic.Report{}, errors.New("bootstrap doctor helper failed")
	}
	report, err := punarodiagnostic.Decode(strings.NewReader(output.buffer.String()))
	if err != nil || report.Component != punarodiagnostic.ComponentBootstrap {
		return punarodiagnostic.Report{}, errors.New("bootstrap doctor helper returned an invalid report")
	}
	return report, nil
}

// RunDoctorHelper executes one decoded direct diagnostic inside the isolated
// child. It is dispatched only by signed Punaro component binaries.
func RunDoctorHelper(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("doctor-bootstrap-report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	encoded := flags.String("request", "", "encoded content-free bootstrap doctor request")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *encoded == "" || len(*encoded) > 192<<10 {
		return 2
	}
	body, err := base64.RawURLEncoding.DecodeString(*encoded)
	if err != nil || len(body) == 0 || len(body) > maximumDoctorHelperRequest {
		return 2
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var payload doctorHelperRequest
	if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF || payload.Directory == "" || len(payload.Keys) > 32 || payload.KeysFile != "" && (!filepath.IsAbs(payload.KeysFile) || filepath.Clean(payload.KeysFile) != payload.KeysFile) {
		return 2
	}
	for keyID, key := range payload.Keys {
		if keyID == "" || len(keyID) > 128 || len(key) != ed25519.PublicKeySize {
			return 2
		}
	}
	report, err := Doctor(context.Background(), DoctorRequest{
		Directory: payload.Directory, MachineID: payload.MachineID, Origin: payload.Origin, Keys: payload.Keys, KeysFile: payload.KeysFile,
		GOOS: payload.GOOS, GOARCH: payload.GOARCH, Now: payload.Now, BootstrapRelease: payload.BootstrapRelease,
	})
	if err != nil || json.NewEncoder(stdout).Encode(report) != nil {
		return 1
	}
	return 0
}
