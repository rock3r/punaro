// punaro-trusted-attachment is the native trusted-relay sender and receiver.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/rock3r/punaro/internal/trustedattachmentclient"
)

type attachmentClient interface {
	Send(context.Context, trustedattachmentclient.SendRequest) (trustedattachmentclient.Artifact, error)
	Receive(context.Context, string, string) (string, error)
	Delete(context.Context, string, string) (trustedattachmentclient.Deletion, error)
}

var newClient = func(origin, credential string) (attachmentClient, error) {
	return trustedattachmentclient.New(origin, credential, nil)
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: punaro-trusted-attachment send|receive|delete")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	switch args[0] {
	case "send":
		return runSend(ctx, args[1:], stdout, stderr)
	case "receive":
		return runReceive(ctx, args[1:], stdout, stderr)
	case "delete":
		return runDelete(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintln(stderr, "unsupported trusted attachment command")
		return 2
	}
}

type commonFlags struct {
	origin         *string
	credentialFile *string
}

func addCommonFlags(flags *flag.FlagSet) commonFlags {
	return commonFlags{origin: flags.String("origin", "", "fixed Punaro HTTPS origin"), credentialFile: flags.String("credential-file", "", "absolute protected device credential file")}
}

func clientFromFlags(common commonFlags) (attachmentClient, error) {
	if common.origin == nil || common.credentialFile == nil || *common.origin == "" || !filepath.IsAbs(*common.credentialFile) {
		return nil, errors.New("origin and absolute credential file are required")
	}
	credential, err := readCredential(*common.credentialFile)
	if err != nil {
		return nil, err
	}
	return newClient(*common.origin, credential)
}

func runSend(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("send", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := addCommonFlags(flags)
	project := flags.String("project", "", "opaque project ID")
	idempotency := flags.String("idempotency-key", "", "stable operation UUID")
	path := flags.String("file", "", "local regular file")
	name := flags.String("name", "", "display name")
	mediaType := flags.String("media-type", "application/octet-stream", "portable media type")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *project == "" || *idempotency == "" || *path == "" || *name == "" {
		return 2
	}
	client, err := clientFromFlags(common)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trusted attachment client error: %v\n", err)
		return 2
	}
	artifact, err := client.Send(ctx, trustedattachmentclient.SendRequest{ProjectID: *project, IdempotencyKey: *idempotency, Path: *path, DisplayName: *name, MediaType: *mediaType})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trusted attachment send failed: %v\n", err)
		return 1
	}
	return writeOutput(stdout, map[string]any{"artifact_id": artifact.ArtifactID, "project_id": artifact.ProjectID, "size_bytes": artifact.SizeBytes, "sha256": hex.EncodeToString(artifact.SHA256[:]), "state": artifact.State})
}

func runReceive(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("receive", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := addCommonFlags(flags)
	artifact := flags.String("artifact", "", "opaque artifact ID")
	root := flags.String("download-root", "", "existing safe download root")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *artifact == "" || !filepath.IsAbs(*root) {
		return 2
	}
	client, err := clientFromFlags(common)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trusted attachment client error: %v\n", err)
		return 2
	}
	name, err := client.Receive(ctx, *artifact, *root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trusted attachment receive failed: %v\n", err)
		return 1
	}
	return writeOutput(stdout, map[string]string{"artifact_id": *artifact, "name": name})
}

func runDelete(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("delete", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := addCommonFlags(flags)
	artifact := flags.String("artifact", "", "opaque artifact ID")
	idempotency := flags.String("idempotency-key", "", "stable operation UUID")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *artifact == "" || *idempotency == "" {
		return 2
	}
	client, err := clientFromFlags(common)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trusted attachment client error: %v\n", err)
		return 2
	}
	deletion, err := client.Delete(ctx, *artifact, *idempotency)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trusted attachment delete failed: %v\n", err)
		return 1
	}
	return writeOutput(stdout, map[string]string{"artifact_id": deletion.ArtifactID, "project_id": deletion.ProjectID, "state": deletion.State})
}

func readCredential(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !privateCredentialFile(info) {
		return "", errors.New("device credential file is unsafe")
	}
	file, err := os.Open(path) // #nosec G304 -- explicit absolute protected credential file.
	if err != nil {
		return "", errors.New("device credential file is unavailable")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return "", errors.New("device credential file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 513))
	credential := strings.TrimSuffix(string(raw), "\n")
	if err != nil || len(raw) == 0 || len(raw) > 512 || credential == "" || strings.ContainsAny(credential, " \t\r\n") {
		return "", errors.New("device credential file is invalid")
	}
	return credential, nil
}

func writeOutput(destination io.Writer, value any) int {
	if err := json.NewEncoder(destination).Encode(value); err != nil {
		return 1
	}
	return 0
}
