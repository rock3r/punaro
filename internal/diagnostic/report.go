// Package diagnostic defines the bounded, content-free report exchanged by
// Punaro doctor commands. Reports deliberately contain no free-form detail:
// callers map local failures to stable check and remediation codes before
// crossing a process or machine boundary.
package diagnostic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// Supported diagnostic components.
const (
	// SchemaVersion identifies the JSON report contract.
	SchemaVersion = 1
	// MaximumChecks bounds work and output accepted by fleet aggregation.
	MaximumChecks = 128
	// MaximumReportBytes bounds one encoded report.
	MaximumReportBytes = 64 << 10

	// ExitHealthy is returned when every required check passes.
	ExitHealthy = 0
	// ExitUnhealthy is returned when at least one required check does not pass.
	ExitUnhealthy = 1
)

// Component identifies a closed doctor report producer.
type Component string

// Supported diagnostic components.
const (
	ComponentServer    Component = "server"
	ComponentAdapter   Component = "adapter"
	ComponentBootstrap Component = "bootstrap"
	ComponentTelegram  Component = "telegram"
	ComponentFleet     Component = "fleet"
)

// Status is the bounded outcome of one diagnostic check.
type Status string

// Stable diagnostic check outcomes.
const (
	StatusPass        Status = "pass"
	StatusFail        Status = "fail"
	StatusUnavailable Status = "unavailable"
)

// Identity contains only public, bounded compatibility identifiers. Empty
// fields are omitted when a component cannot report them safely.
type Identity struct {
	MachineID       string   `json:"machine_id,omitempty"`
	Release         string   `json:"release,omitempty"`
	ReleaseSequence int64    `json:"release_sequence,omitempty"`
	CatalogSequence int64    `json:"catalog_sequence,omitempty"`
	Protocol        int64    `json:"protocol,omitempty"`
	StorageSchema   int64    `json:"storage_schema,omitempty"`
	ArtifactDigest  string   `json:"artifact_digest,omitempty"`
	Platform        string   `json:"platform,omitempty"`
	PluginVersion   string   `json:"plugin_version,omitempty"`
	SkillSetDigest  string   `json:"skill_set_digest,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
}

// Check is one stable diagnostic assertion. Remediation is an enumerated code,
// never a command or a provider error.
type Check struct {
	Code        string `json:"code"`
	Status      Status `json:"status"`
	Required    bool   `json:"required"`
	Remediation string `json:"remediation,omitempty"`
}

// Report is the canonical doctor output for one component.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Component     Component `json:"component"`
	Identity      Identity  `json:"identity"`
	Healthy       bool      `json:"healthy"`
	Checks        []Check   `json:"checks"`
}

var (
	stableCodePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	machineIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	releasePattern    = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]{0,63})?(?:\+[0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
	platformPattern   = regexp.MustCompile(`^[a-z0-9]+-[a-z0-9][a-z0-9_]{0,31}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Pass creates a required successful check.
func Pass(code string) Check {
	return Check{Code: code, Status: StatusPass, Required: true}
}

// Fail creates a required failed check.
func Fail(code, remediation string) Check {
	return Check{Code: code, Status: StatusFail, Required: true, Remediation: remediation}
}

// OptionalFail creates a failed check which does not make the component
// unhealthy.
func OptionalFail(code, remediation string) Check {
	return Check{Code: code, Status: StatusFail, Remediation: remediation}
}

// Unavailable creates a required check that could not be executed.
func Unavailable(code, remediation string) Check {
	return Check{Code: code, Status: StatusUnavailable, Required: true, Remediation: remediation}
}

// OptionalUnavailable creates an unavailable optional check.
func OptionalUnavailable(code, remediation string) Check {
	return Check{Code: code, Status: StatusUnavailable, Remediation: remediation}
}

// New validates and canonicalizes one report.
func New(component Component, identity Identity, checks []Check) (Report, error) {
	if !validComponent(component) {
		return Report{}, errors.New("invalid diagnostic component")
	}
	if err := validateIdentity(identity); err != nil {
		return Report{}, err
	}
	if len(checks) > MaximumChecks {
		return Report{}, errors.New("too many diagnostic checks")
	}

	canonical := append([]Check(nil), checks...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Code < canonical[j].Code })
	healthy := true
	for index := range canonical {
		check := canonical[index]
		if err := validateCheck(check); err != nil {
			return Report{}, err
		}
		if index > 0 && canonical[index-1].Code == check.Code {
			return Report{}, errors.New("duplicate diagnostic check")
		}
		if check.Required && check.Status != StatusPass {
			healthy = false
		}
	}

	return Report{
		SchemaVersion: SchemaVersion,
		Component:     component,
		Identity:      identity,
		Healthy:       healthy,
		Checks:        canonical,
	}, nil
}

// ExitCode maps a validated report outcome to the stable doctor exit contract.
func ExitCode(report Report) int {
	if report.Healthy {
		return ExitHealthy
	}
	return ExitUnhealthy
}

// Decode strictly parses one bounded, canonical report.
func Decode(input io.Reader) (Report, error) {
	if input == nil {
		return Report{}, errors.New("missing diagnostic report")
	}
	body, err := io.ReadAll(io.LimitReader(input, MaximumReportBytes+1))
	if err != nil || len(body) == 0 || len(body) > MaximumReportBytes {
		return Report{}, errors.New("diagnostic report is invalid")
	}
	if rejectDuplicateJSONFields(body) != nil {
		return Report{}, errors.New("diagnostic report is invalid")
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, errors.New("diagnostic report is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Report{}, errors.New("diagnostic report has trailing data")
	}

	canonical, err := New(report.Component, report.Identity, report.Checks)
	if err != nil || report.SchemaVersion != SchemaVersion || !reflect.DeepEqual(report, canonical) {
		return Report{}, errors.New("diagnostic report is not canonical")
	}
	return canonical, nil
}

func rejectDuplicateJSONFields(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var scanValue func(int) error
	scanValue = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting is too deep")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("duplicate JSON object key")
				}
				seen[key] = struct{}{}
				if err := scanValue(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case '[':
			for decoder.More() {
				if err := scanValue(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := scanValue(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func validComponent(component Component) bool {
	switch component {
	case ComponentServer, ComponentAdapter, ComponentBootstrap, ComponentTelegram, ComponentFleet:
		return true
	default:
		return false
	}
}

func validateIdentity(identity Identity) error {
	if identity.MachineID != "" && !machineIDPattern.MatchString(identity.MachineID) {
		return errors.New("invalid diagnostic machine identity")
	}
	if identity.Release != "" && !releasePattern.MatchString(identity.Release) {
		return errors.New("invalid diagnostic release")
	}
	if identity.ReleaseSequence < 0 || identity.CatalogSequence < 0 || identity.Protocol < 0 || identity.StorageSchema < 0 {
		return errors.New("invalid diagnostic compatibility identity")
	}
	if identity.ArtifactDigest != "" && !digestPattern.MatchString(identity.ArtifactDigest) {
		return errors.New("invalid diagnostic artifact digest")
	}
	if identity.Platform != "" && !platformPattern.MatchString(identity.Platform) {
		return errors.New("invalid diagnostic platform")
	}
	if identity.PluginVersion != "" && !releasePattern.MatchString(identity.PluginVersion) {
		return errors.New("invalid diagnostic plugin version")
	}
	if identity.SkillSetDigest != "" && !digestPattern.MatchString(identity.SkillSetDigest) {
		return errors.New("invalid diagnostic skill set digest")
	}
	if len(identity.Capabilities) > 16 || !sort.StringsAreSorted(identity.Capabilities) {
		return errors.New("invalid diagnostic capabilities")
	}
	for index, capability := range identity.Capabilities {
		if !validStableCode(capability) || index > 0 && identity.Capabilities[index-1] == capability {
			return errors.New("invalid diagnostic capabilities")
		}
	}
	return nil
}

func validateCheck(check Check) error {
	if !validStableCode(check.Code) {
		return fmt.Errorf("invalid diagnostic check code %q", check.Code)
	}
	switch check.Status {
	case StatusPass:
		if check.Remediation != "" {
			return errors.New("passing diagnostic check has remediation")
		}
	case StatusFail, StatusUnavailable:
		if !validStableCode(check.Remediation) {
			return errors.New("failed diagnostic check has invalid remediation")
		}
	default:
		return errors.New("invalid diagnostic check status")
	}
	return nil
}

func validStableCode(value string) bool {
	return len(value) <= 64 && stableCodePattern.MatchString(value) && !strings.Contains(value, "token")
}
