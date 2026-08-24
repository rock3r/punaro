package diagnostic

import (
	"errors"
	"reflect"
	"sort"

	punarorelease "github.com/rock3r/punaro/internal/release"
)

// FleetTarget identifies one independently collected component report.
type FleetTarget struct {
	MachineID string
	Component Component
}

// FleetPolicy is derived from operator expectations and verified release
// documents. It contains no credentials or remote-management capability.
type FleetPolicy struct {
	Expected           []FleetTarget
	CatalogSequence    int64
	Catalog            map[string]int64
	SupportedFrom      map[string][]string
	ProtocolMin        int64
	ProtocolMax        int64
	GatewayProtocolMin int64
	GatewayProtocolMax int64
	ClientProtocolMin  int64
	ClientProtocolMax  int64
	SchemaMin          int64
	SchemaMax          int64
}

// AggregateFleet compares already-produced doctor reports. It never opens a
// network connection or reads component state directly.
func AggregateFleet(reports []Report, policy FleetPolicy) (Report, error) {
	if len(reports) == 0 || len(reports) > MaximumChecks || policy.CatalogSequence < 1 || len(policy.Catalog) == 0 || len(policy.Catalog) > 32 || len(policy.Expected) == 0 || len(policy.Expected) > MaximumChecks || !validFleetRange(policy.ProtocolMin, policy.ProtocolMax) || !validFleetRange(policy.GatewayProtocolMin, policy.GatewayProtocolMax) || !validFleetRange(policy.ClientProtocolMin, policy.ClientProtocolMax) || !validFleetRange(policy.SchemaMin, policy.SchemaMax) {
		return Report{}, errors.New("invalid fleet diagnostic input")
	}
	expected := make(map[string]FleetTarget, len(policy.Expected))
	for _, target := range policy.Expected {
		if target.MachineID == "" || !machineIDPattern.MatchString(target.MachineID) || !validComponent(target.Component) || target.Component == ComponentFleet {
			return Report{}, errors.New("invalid fleet diagnostic policy")
		}
		key := fleetKey(target.MachineID, target.Component)
		if _, duplicate := expected[key]; duplicate {
			return Report{}, errors.New("invalid fleet diagnostic policy")
		}
		expected[key] = target
	}
	for release, sequence := range policy.Catalog {
		if !punarorelease.ValidProductReleaseName(release) || sequence < 1 {
			return Report{}, errors.New("invalid fleet diagnostic catalog")
		}
	}

	seen := make(map[string]int, len(reports))
	releases := make(map[string]int64)
	protocols := make(map[int64]struct{})
	schemas := make(map[int64]struct{})
	plugins := make(map[string]struct{})
	skills := make(map[string]struct{})
	allHealthy := true
	catalogOK := true
	protocolCompatible := true
	pluginOK := true
	skillOK := true
	for _, report := range reports {
		canonical, err := New(report.Component, report.Identity, report.Checks)
		if err != nil || report.SchemaVersion != SchemaVersion || !reflect.DeepEqual(report, canonical) || report.Component == ComponentFleet || report.Identity.MachineID == "" {
			return Report{}, errors.New("invalid fleet diagnostic report")
		}
		key := fleetKey(report.Identity.MachineID, report.Component)
		seen[key]++
		allHealthy = allHealthy && report.Healthy
		sequence, allowed := policy.Catalog[report.Identity.Release]
		if !allowed || sequence != report.Identity.ReleaseSequence {
			catalogOK = false
		}
		releases[report.Identity.Release] = report.Identity.ReleaseSequence
		if report.Identity.Protocol > 0 {
			protocols[report.Identity.Protocol] = struct{}{}
			minimum, maximum := fleetProtocolRange(report.Component, policy)
			if minimum > 0 && (report.Identity.Protocol < minimum || report.Identity.Protocol > maximum) {
				protocolCompatible = false
			}
		} else {
			protocolCompatible = false
		}
		if report.Identity.StorageSchema > 0 {
			schemas[report.Identity.StorageSchema] = struct{}{}
			if policy.SchemaMin > 0 && (report.Identity.StorageSchema < policy.SchemaMin || report.Identity.StorageSchema > policy.SchemaMax) {
				schemas[0] = struct{}{}
			}
		}
		if report.Component == ComponentAdapter {
			if report.Identity.PluginVersion == "" {
				pluginOK = false
			} else {
				plugins[report.Identity.PluginVersion] = struct{}{}
			}
			if report.Identity.SkillSetDigest == "" {
				skillOK = false
			} else {
				skills[report.Identity.SkillSetDigest] = struct{}{}
			}
		}
	}

	expectedOK := true
	for key := range expected {
		if seen[key] != 1 {
			expectedOK = false
		}
	}
	uniqueOK := true
	for _, count := range seen {
		if count > 1 {
			uniqueOK = false
		}
	}

	checks := []Check{
		Pass("report_inputs"),
		fleetBoolCheck(allHealthy, "component_health", "repair_unhealthy_components"),
		fleetBoolCheck(expectedOK, "expected_components", "collect_missing_reports"),
		fleetBoolCheck(uniqueOK, "machine_identity_uniqueness", "remove_duplicate_reports"),
		fleetBoolCheck(catalogOK, "release_catalog_membership", "install_catalog_release"),
		fleetBoolCheck(len(releases) == 1, "release_skew", "complete_fleet_update"),
		fleetBoolCheck(len(protocols) <= 1, "protocol_skew", "install_compatible_release"),
		fleetBoolCheck(protocolCompatible, "protocol_compatibility", "install_compatible_release"),
		fleetBoolCheck(len(schemas) <= 1, "schema_skew", "complete_server_update"),
		fleetBoolCheck(supportedFleetEdges(releases, policy.SupportedFrom), "upgrade_edges", "follow_supported_upgrade_edge"),
		fleetBoolCheck(pluginOK && len(plugins) <= 1, "plugin_skew", "install_matching_plugin"),
		fleetBoolCheck(skillOK && len(skills) <= 1, "skill_set_skew", "install_matching_skill_set"),
	}
	return New(ComponentFleet, Identity{CatalogSequence: policy.CatalogSequence}, checks)
}

func validFleetRange(minimum, maximum int64) bool {
	return minimum == 0 && maximum == 0 || minimum > 0 && maximum >= minimum
}

func fleetProtocolRange(component Component, policy FleetPolicy) (int64, int64) {
	switch component {
	case ComponentAdapter, ComponentBootstrap:
		if policy.ClientProtocolMin > 0 {
			return policy.ClientProtocolMin, policy.ClientProtocolMax
		}
	case ComponentServer, ComponentTelegram:
		if policy.GatewayProtocolMin > 0 {
			return policy.GatewayProtocolMin, policy.GatewayProtocolMax
		}
	}
	return policy.ProtocolMin, policy.ProtocolMax
}

func fleetKey(machineID string, component Component) string {
	return machineID + "\x00" + string(component)
}

func fleetBoolCheck(ok bool, code, remediation string) Check {
	if ok {
		return Pass(code)
	}
	return Fail(code, remediation)
}

func supportedFleetEdges(releases map[string]int64, supported map[string][]string) bool {
	if len(releases) <= 1 {
		return true
	}
	type releaseSequence struct {
		release  string
		sequence int64
	}
	ordered := make([]releaseSequence, 0, len(releases))
	for release, sequence := range releases {
		ordered = append(ordered, releaseSequence{release: release, sequence: sequence})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].sequence < ordered[j].sequence })
	target := ordered[len(ordered)-1].release
	allowed := make(map[string]struct{}, len(supported[target]))
	for _, source := range supported[target] {
		allowed[source] = struct{}{}
	}
	for _, source := range ordered[:len(ordered)-1] {
		if _, ok := allowed[source.release]; !ok {
			return false
		}
	}
	return true
}
