package diagnostic

import "testing"

func TestFleetDetectsMissingDuplicateCatalogAndCompatibilitySkew(t *testing.T) {
	reports := []Report{
		mustFleetInput(t, ComponentServer, Identity{MachineID: "punaro-lxc", Release: "v0.1.0-alpha.2", ReleaseSequence: 2, Protocol: 2, StorageSchema: 44, Platform: "linux-arm64"}),
		mustFleetInput(t, ComponentAdapter, Identity{MachineID: "mac-studio", Release: "v0.1.0-alpha.1", ReleaseSequence: 1, Protocol: 1, Platform: "darwin-arm64", PluginVersion: "v0.1.0-alpha.1", SkillSetDigest: "sha256:" + digestA}),
		mustFleetInput(t, ComponentAdapter, Identity{MachineID: "mac-studio", Release: "v0.1.0-alpha.1", ReleaseSequence: 1, Protocol: 1, Platform: "darwin-arm64", PluginVersion: "v0.1.0-alpha.1", SkillSetDigest: "sha256:" + digestA}),
		mustFleetInput(t, ComponentAdapter, Identity{MachineID: "mattone", Release: "v9.9.9", ReleaseSequence: 99, Protocol: 1, Platform: "windows-amd64", PluginVersion: "v0.1.0-alpha.2", SkillSetDigest: "sha256:" + digestB}),
	}
	policy := FleetPolicy{
		Expected:        []FleetTarget{{MachineID: "punaro-lxc", Component: ComponentServer}, {MachineID: "mac-studio", Component: ComponentAdapter}, {MachineID: "macbook", Component: ComponentAdapter}, {MachineID: "mattone", Component: ComponentAdapter}},
		CatalogSequence: 2,
		Catalog:         map[string]int64{"v0.1.0-alpha.1": 1, "v0.1.0-alpha.2": 2},
		SupportedFrom:   map[string][]string{"v0.1.0-alpha.2": {"v0.1.0-alpha.1"}},
	}
	report, err := AggregateFleet(reports, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"expected_components", "machine_identity_uniqueness", "release_catalog_membership", "release_skew", "protocol_skew", "upgrade_edges", "plugin_skew", "skill_set_skew"} {
		if fleetStatus(report, code) != StatusFail {
			t.Fatalf("%s=%s report=%#v", code, fleetStatus(report, code), report)
		}
	}
}

func TestFleetHealthyWithIndependentReportsAndSupportedRollingEdge(t *testing.T) {
	reports := []Report{
		mustFleetInput(t, ComponentServer, Identity{MachineID: "punaro-lxc", Release: "v0.1.0-alpha.2", ReleaseSequence: 2, Protocol: 1, StorageSchema: 44, Platform: "linux-arm64"}),
		mustFleetInput(t, ComponentTelegram, Identity{MachineID: "telegram-gateway", Release: "v0.1.0-alpha.2", ReleaseSequence: 2, Protocol: 1, Platform: "linux-arm64"}),
		mustFleetInput(t, ComponentAdapter, Identity{MachineID: "mac-studio", Release: "v0.1.0-alpha.2", ReleaseSequence: 2, Protocol: 1, Platform: "darwin-arm64", PluginVersion: "v0.1.0-alpha.2", SkillSetDigest: "sha256:" + digestA}),
		mustFleetInput(t, ComponentAdapter, Identity{MachineID: "macbook", Release: "v0.1.0-alpha.2", ReleaseSequence: 2, Protocol: 1, Platform: "darwin-arm64", PluginVersion: "v0.1.0-alpha.2", SkillSetDigest: "sha256:" + digestA}),
		mustFleetInput(t, ComponentAdapter, Identity{MachineID: "mattone", Release: "v0.1.0-alpha.2", ReleaseSequence: 2, Protocol: 1, Platform: "windows-amd64", PluginVersion: "v0.1.0-alpha.2", SkillSetDigest: "sha256:" + digestA}),
	}
	expected := make([]FleetTarget, 0, len(reports))
	for _, report := range reports {
		expected = append(expected, FleetTarget{MachineID: report.Identity.MachineID, Component: report.Component})
	}
	report, err := AggregateFleet(reports, FleetPolicy{Expected: expected, CatalogSequence: 2, Catalog: map[string]int64{"v0.1.0-alpha.1": 1, "v0.1.0-alpha.2": 2}, SupportedFrom: map[string][]string{"v0.1.0-alpha.2": {"v0.1.0-alpha.1"}}, ProtocolMin: 1, ProtocolMax: 1, SchemaMin: 44, SchemaMax: 44})
	if err != nil || !report.Healthy || report.Identity.CatalogSequence != 2 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
}

func TestFleetUsesComponentSpecificProtocolRanges(t *testing.T) {
	reports := []Report{
		mustFleetInput(t, ComponentServer, Identity{MachineID: "punaro-lxc", Release: "v0.1.0-alpha.2", ReleaseSequence: 2, Protocol: 2, Platform: "linux-arm64"}),
		mustFleetInput(t, ComponentAdapter, Identity{MachineID: "mac-studio", Release: "v0.1.0-alpha.2", ReleaseSequence: 2, Protocol: 1, Platform: "darwin-arm64", PluginVersion: "v0.1.0-alpha.2", SkillSetDigest: "sha256:" + digestA}),
	}
	report, err := AggregateFleet(reports, FleetPolicy{
		Expected:        []FleetTarget{{MachineID: "punaro-lxc", Component: ComponentServer}, {MachineID: "mac-studio", Component: ComponentAdapter}},
		CatalogSequence: 2, Catalog: map[string]int64{"v0.1.0-alpha.2": 2},
		GatewayProtocolMin: 2, GatewayProtocolMax: 2, ClientProtocolMin: 1, ClientProtocolMax: 1,
	})
	if err != nil || fleetStatus(report, "protocol_skew") != StatusFail || fleetStatus(report, "protocol_compatibility") != StatusPass {
		t.Fatalf("component-specific versions must still report rolling skew: report=%#v err=%v", report, err)
	}

	reports[0].Identity.Protocol = 3
	report, err = AggregateFleet(reports, FleetPolicy{
		Expected:        []FleetTarget{{MachineID: "punaro-lxc", Component: ComponentServer}, {MachineID: "mac-studio", Component: ComponentAdapter}},
		CatalogSequence: 2, Catalog: map[string]int64{"v0.1.0-alpha.2": 2},
		GatewayProtocolMin: 2, GatewayProtocolMax: 2, ClientProtocolMin: 1, ClientProtocolMax: 1,
	})
	if err != nil || fleetStatus(report, "protocol_compatibility") != StatusFail {
		t.Fatalf("out-of-range gateway protocol was accepted: report=%#v err=%v", report, err)
	}
}

func TestFleetRejectsMissingProtocolIdentity(t *testing.T) {
	report := mustFleetInput(t, ComponentAdapter, Identity{MachineID: "mac-studio", Release: "v0.1.0-alpha.2", ReleaseSequence: 2, Platform: "darwin-arm64", PluginVersion: "v0.1.0-alpha.2", SkillSetDigest: "sha256:" + digestA})
	fleet, err := AggregateFleet([]Report{report}, FleetPolicy{
		Expected:          []FleetTarget{{MachineID: "mac-studio", Component: ComponentAdapter}},
		CatalogSequence:   2,
		Catalog:           map[string]int64{"v0.1.0-alpha.2": 2},
		ClientProtocolMin: 1,
		ClientProtocolMax: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fleetStatus(fleet, "protocol_compatibility") != StatusFail || fleet.Healthy {
		t.Fatalf("missing protocol identity accepted: %#v", fleet)
	}
}

const (
	digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func mustFleetInput(t *testing.T, component Component, identity Identity) Report {
	t.Helper()
	report, err := New(component, identity, []Check{Pass("ready")})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func fleetStatus(report Report, code string) Status {
	for _, check := range report.Checks {
		if check.Code == code {
			return check.Status
		}
	}
	return ""
}
