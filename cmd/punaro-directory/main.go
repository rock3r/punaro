// punaro-directory provisions public directory snapshots without exposing
// private material in command output. It is intentionally an operator tool,
// not an attachment client.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: punaro-directory <keygen|id|build>"))
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "id":
		err = runID(os.Args[2:])
	case "build":
		err = runBuild(os.Args[2:])
	default:
		err = errors.New("usage: punaro-directory <keygen|id|build>")
	}
	if err != nil {
		fail(err)
	}
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("punaro-directory keygen", flag.ContinueOnError)
	algorithm := fs.String("algorithm", "ed25519", "ed25519 or x25519")
	path := fs.String("private-key-file", "", "new private key file (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || !filepath.IsAbs(*path) {
		return errors.New("--private-key-file must be an absolute path")
	}
	var private, public []byte
	var err error
	switch *algorithm {
	case "ed25519":
		public, private, err = ed25519.GenerateKey(rand.Reader)
	case "x25519":
		key, keyErr := ecdh.X25519().GenerateKey(rand.Reader)
		err = keyErr
		if err == nil {
			private, public = key.Bytes(), key.PublicKey().Bytes()
		}
	default:
		return errors.New("--algorithm must be ed25519 or x25519")
	}
	if err != nil {
		return err
	}
	if err := writeNewPrivateFile(*path, private); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"algorithm": *algorithm, "public_key": base64.RawURLEncoding.EncodeToString(public)})
}

func runID(args []string) error {
	fs := flag.NewFlagSet("punaro-directory id", flag.ContinueOnError)
	size := fs.Int("bytes", 0, "public identifier size: 16 or 32")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *size != 16 && *size != 32 {
		return errors.New("--bytes must be 16 or 32")
	}
	b := make([]byte, *size)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"id": base64.RawURLEncoding.EncodeToString(b)})
}

func runBuild(args []string) error {
	fs := flag.NewFlagSet("punaro-directory build", flag.ContinueOnError)
	configPath := fs.String("config", "", "non-secret directory JSON manifest")
	rootPath := fs.String("root-private-key-file", "", "absolute private Ed25519 root key file")
	output := fs.String("output", "", "absolute snapshot output file")
	ttl := fs.Duration("ttl", 2*time.Minute, "snapshot lifetime (1s-5m)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *rootPath == "" || *output == "" || !filepath.IsAbs(*configPath) || !filepath.IsAbs(*rootPath) || !filepath.IsAbs(*output) {
		return errors.New("--config, --root-private-key-file, and --output must be absolute paths")
	}
	if *ttl < time.Second || *ttl > 5*time.Minute {
		return errors.New("--ttl must be between 1s and 5m")
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return fmt.Errorf("decode public directory manifest: %w", err)
	}
	var config directoryConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return fmt.Errorf("decode public directory manifest: %w", err)
	}
	root, err := attachmentv2.LoadPrivateEd25519KeyFile(*rootPath)
	if err != nil {
		return err
	}
	snapshot, _, err := buildSnapshot(config, root, time.Now().UTC(), *ttl)
	if err != nil {
		return err
	}
	return writeSnapshot(*output, snapshot)
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", name)
			}
			seen[name] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}

type directoryConfig struct {
	Audience        string                 `json:"audience"`
	RootKeyID       string                 `json:"root_key_id"`
	Sequence        uint64                 `json:"sequence"`
	RevocationEpoch uint64                 `json:"revocation_epoch"`
	Entries         []directoryEntryConfig `json:"entries"`
}
type directoryEntryConfig struct {
	Device     *directoryDeviceConfig     `json:"device,omitempty"`
	Membership *directoryMembershipConfig `json:"membership,omitempty"`
	Issuer     *directoryIssuerConfig     `json:"issuer,omitempty"`
}
type directoryDeviceConfig struct {
	DeviceID         string `json:"device_id"`
	Generation       uint64 `json:"generation"`
	SigningKeyID     string `json:"signing_key_id"`
	SigningPublicKey string `json:"signing_public_key"`
	HPKEKeyID        string `json:"hpke_key_id"`
	HPKEPublicKey    string `json:"hpke_public_key"`
	Revoked          bool   `json:"revoked"`
}
type directoryMembershipConfig struct {
	ConversationID      string `json:"conversation_id"`
	SenderDeviceID      string `json:"sender_device_id"`
	SenderGeneration    uint64 `json:"sender_generation"`
	RecipientDeviceID   string `json:"recipient_device_id"`
	RecipientGeneration uint64 `json:"recipient_generation"`
	Commitment          string `json:"commitment"`
	Revoked             bool   `json:"revoked"`
}
type directoryIssuerConfig struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Revoked   bool   `json:"revoked"`
}

func buildSnapshot(config directoryConfig, root ed25519.PrivateKey, now time.Time, ttl time.Duration) ([]byte, attachmentv2.DirectoryHead, error) {
	audience, err := fixed32(config.Audience)
	if err != nil {
		return nil, attachmentv2.DirectoryHead{}, err
	}
	rootID, err := fixed32(config.RootKeyID)
	if err != nil || config.Sequence == 0 {
		return nil, attachmentv2.DirectoryHead{}, errors.New("invalid public directory head")
	}
	type indexedEntry struct {
		index int
		entry attachmentv2.DirectoryEntry
	}
	indexed := make([]indexedEntry, 0, len(config.Entries))
	for index, configured := range config.Entries {
		kinds := 0
		if configured.Device != nil {
			kinds++
		}
		if configured.Membership != nil {
			kinds++
		}
		if configured.Issuer != nil {
			kinds++
		}
		if kinds != 1 {
			return nil, attachmentv2.DirectoryHead{}, errors.New("each directory entry must contain exactly one kind")
		}
		if configured.Device == nil {
			continue
		}
		d := *configured.Device
		id, e := fixed16(d.DeviceID)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		signID, e := fixed32(d.SigningKeyID)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		sign, e := fixed32(d.SigningPublicKey)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		hpkeID, e := fixed32(d.HPKEKeyID)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		hpke, e := fixed32(d.HPKEPublicKey)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		indexed = append(indexed, indexedEntry{index, attachmentv2.DirectoryEntry{Device: &attachmentv2.DirectoryDevice{DeviceID: id, Generation: d.Generation, SigningKeyID: signID, SigningPublicKey: sign, HPKEKeyID: hpkeID, HPKEPublicKey: hpke, Revoked: d.Revoked}}})
	}
	for index, configured := range config.Entries {
		if configured.Issuer == nil {
			continue
		}
		i := *configured.Issuer
		id, e := fixed32(i.KeyID)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		key, e := fixed32(i.PublicKey)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		indexed = append(indexed, indexedEntry{index, attachmentv2.DirectoryEntry{Issuer: &attachmentv2.DirectoryPermitIssuer{KeyID: id, PublicKey: key, Revoked: i.Revoked}}})
	}
	for index, configured := range config.Entries {
		if configured.Membership == nil {
			continue
		}
		m := *configured.Membership
		c, e := fixed16(m.ConversationID)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		s, e := fixed16(m.SenderDeviceID)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		r, e := fixed16(m.RecipientDeviceID)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		commitment, e := fixed32(m.Commitment)
		if e != nil {
			return nil, attachmentv2.DirectoryHead{}, e
		}
		indexed = append(indexed, indexedEntry{index, attachmentv2.DirectoryEntry{Membership: &attachmentv2.DirectoryMembership{ConversationID: c, SenderDeviceID: s, SenderGeneration: m.SenderGeneration, RecipientDeviceID: r, RecipientGeneration: m.RecipientGeneration, Commitment: commitment, Revoked: m.Revoked}}})
	}
	sort.Slice(indexed, func(a, b int) bool { return indexed[a].index < indexed[b].index })
	entries := make([]attachmentv2.DirectoryEntry, 0, len(indexed))
	for _, value := range indexed {
		entries = append(entries, value.entry)
	}
	hashes, err := attachmentv2.DirectoryEntryHashes(entries)
	if err != nil {
		return nil, attachmentv2.DirectoryHead{}, err
	}
	issued := now.UTC().Truncate(time.Second)
	issuedSeconds, expiresSeconds := issued.Unix(), issued.Add(ttl).Unix()
	if issuedSeconds < 0 || expiresSeconds < 0 {
		return nil, attachmentv2.DirectoryHead{}, errors.New("directory snapshot time is not representable")
	}
	head := attachmentv2.DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: uint64(len(entries)), TreeRoot: attachmentv2.DirectoryMerkleRoot(hashes), Sequence: config.Sequence, IssuedAt: uint64(issuedSeconds), ExpiresAt: uint64(expiresSeconds), RevocationEpoch: config.RevocationEpoch} // #nosec G115 -- both values are checked non-negative above.
	if err := attachmentv2.SignDirectoryHead(&head, root); err != nil {
		return nil, attachmentv2.DirectoryHead{}, err
	}
	rawHead, err := attachmentv2.EncodeDirectoryHead(head)
	if err != nil {
		return nil, attachmentv2.DirectoryHead{}, err
	}
	raw, err := attachmentv2.EncodeDirectorySnapshot(attachmentv2.DirectorySnapshot{RawHead: rawHead, Entries: entries, Proof: &attachmentv2.FullConsistencyProof{LeafHashes: hashes}})
	return raw, head, err
}

func fixed16(s string) ([16]byte, error) {
	var out [16]byte
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil || len(b) != len(out) || base64.RawURLEncoding.EncodeToString(b) != s {
		return out, errors.New("expected canonical 16-byte base64url value")
	}
	copy(out[:], b)
	return out, nil
}
func fixed32(s string) ([32]byte, error) {
	var out [32]byte
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil || len(b) != len(out) || base64.RawURLEncoding.EncodeToString(b) != s {
		return out, errors.New("expected canonical 32-byte base64url value")
	}
	copy(out[:], b)
	return out, nil
}
func writeNewPrivateFile(path string, private []byte) error {
	parent, err := requirePrivateParent(path)
	if err != nil {
		return err
	}
	f, err := openNewPrivateOutput(path, parent)
	if err != nil {
		return err
	}
	_, err = f.WriteString(base64.RawURLEncoding.EncodeToString(private))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func writeSnapshot(path string, raw []byte) error {
	parent, err := requirePrivateParent(path)
	if err != nil {
		return err
	}
	f, err := openNewPrivateOutput(path, parent)
	if err != nil {
		return errors.New("snapshot output must not already exist; publish a new path then atomically replace it")
	}
	_, err = f.Write(raw)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func requirePrivateParent(path string) (os.FileInfo, error) {
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, errors.New("output parent must be an existing private directory owned by the invoking user")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("output parent must be an existing private directory owned by the invoking user")
	}
	return info, nil
}
func openNewPrivateOutput(path string, expected os.FileInfo) (*os.File, error) {
	parent := filepath.Dir(path)
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	actual, err := directory.Stat()
	_ = directory.Close()
	if err != nil || !sameDirectory(expected, actual) {
		return nil, errors.New("output parent changed while opening")
	}
	file, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	return file, nil
}
func sameDirectory(a, b os.FileInfo) bool {
	left, lok := a.Sys().(*syscall.Stat_t)
	right, rok := b.Sys().(*syscall.Stat_t)
	return lok && rok && left.Dev == right.Dev && left.Ino == right.Ino && left.Uid == right.Uid
}
func fail(err error) { _, _ = fmt.Fprintln(os.Stderr, "punaro-directory:", err); os.Exit(2) }
