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

var requiredComponentCheckCodes = map[Component][]string{
	ComponentServer: {
		"access_admission", "administration_listener_private", "application_credential_file", "attachment_blob_containment", "attachment_blob_directory",
		"backup_directory", "backup_freshness", "blob_storage_private", "compose_manifest_binding", "compose_override", "daemon_environment", "data_directory",
		"database_connection", "database_listener_private", "database_owner", "database_pair", "database_schema", "gateway_release", "gateway_service_enabled",
		"gateway_service_executable", "gateway_service_installed", "gateway_service_last_exit", "gateway_service_restart_state", "gateway_service_running", "health_endpoint",
		"health_listener_private", "host_update_stage", "image_digest_binding", "installed_release", "operator_binary_release", "installation_configuration", "installation_directory", "machine_identity",
		"installation_paths", "maintenance_fence", "migration_manifest_binding", "owner_credential_file", "postgres_major", "readiness_endpoint", "recovery_receipt", "relay_enrollment",
		"relay_protocol", "running_image", "storage_capacity", "storage_credential_isolation", "storage_directory_separation", "tunnel_origin", "tunnel_route",
		"update_recovery", "update_transaction", "verified_backup",
	},
	ComponentAdapter: {
		"adapter_configuration", "adapter_data_directory", "adapter_profile_file", "adapter_service_enabled", "adapter_service_executable", "adapter_service_installed",
		"adapter_service_last_exit", "adapter_service_restart_state", "adapter_service_running", "bootstrap_running_artifact", "bootstrap_selected_artifact", "bootstrap_supervisor",
		"claude_plugin_registration", "client_component_launchers", "client_identity_file", "codex_plugin_registration", "endpoint_attachment", "expired_endpoint_bindings", "expired_role_bindings",
		"installed_release", "installer_path_aliases", "machine_credential_file", "mailbox_executable", "mailbox_mcp", "mailbox_state_directory", "notification_access",
		"notification_enrollment", "notification_origin", "notification_protocol", "notification_transport", "plugin_launcher", "plugin_version", "portable_plugin_registration",
		"relay_access", "relay_enrollment", "relay_origin", "relay_protocol", "relay_transport", "skill_set_parity",
	},
	ComponentBootstrap: {
		"accepted_state", "auto_rollback_state", "bootstrap_directory", "bootstrap_lock", "candidate_health", "candidate_state", "catalog_freshness", "catalog_reachability", "catalog_sequence",
		"catalog_signature", "current_artifact_integrity", "current_catalog_allowed", "current_critical_block", "current_manifest_signature", "current_platform_compatibility",
		"current_slot", "disk_space", "journal_state", "minimum_bootstrap_release", "minimum_recovery_protocol", "previous_artifact_integrity", "previous_catalog_allowed",
		"previous_critical_block", "previous_manifest_signature", "previous_platform_compatibility", "previous_slot", "recovery_state", "release_keys", "rollback_available",
		"run_lock", "running_artifact", "supervisor_process", "swap_state",
	},
	ComponentTelegram: {
		"access_credential_file", "bot_api", "bot_credential_file", "claim_backlog", "claim_backlog_age", "conversation_route_integrity", "cycle_liveness",
		"deleted_topic_target", "gateway_endpoint_attachment", "gateway_endpoint_identity", "gateway_service_enabled", "gateway_service_executable", "gateway_service_installed",
		"gateway_service_last_exit", "gateway_service_restart_state", "gateway_service_running", "installed_release", "machine_credential_file", "message_less_update_stall",
		"notification_access", "notification_enrollment", "notification_origin", "notification_protocol", "notification_transport", "polling_liveness", "relay_access",
		"relay_cycle_liveness", "relay_enrollment", "relay_origin", "relay_protocol", "relay_transport", "retry_state", "running_release", "single_user_policy",
		"state_integrity", "stuck_head_delivery", "successful_cycle_liveness", "telegram_configuration", "telegram_cycle_liveness", "terminal_inbound_rejection",
		"terminal_outbound_rejection", "transient_retry_stall",
	},
}

// RequiredComponentCheckCodes returns the stable component doctor contract
// that a fleet report must contain in full. The returned slice is independent
// of the internal registry and can be safely modified by the caller.
func RequiredComponentCheckCodes(component Component) []string {
	return append([]string(nil), requiredComponentCheckCodes[component]...)
}

// NewComponentReport validates and canonicalizes a non-fleet doctor report,
// including its complete component-specific check contract.
func NewComponentReport(component Component, identity Identity, checks []Check) (Report, error) {
	report, err := New(component, identity, checks)
	if err != nil {
		return Report{}, err
	}
	if component == ComponentFleet || !hasRequiredComponentChecks(report) {
		return Report{}, errors.New("incomplete component diagnostic report")
	}
	return report, nil
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
	schemaCompatible := true
	pluginOK := true
	skillOK := true
	for _, report := range reports {
		canonical, err := New(report.Component, report.Identity, report.Checks)
		if err != nil || report.SchemaVersion != SchemaVersion || !reflect.DeepEqual(report, canonical) || report.Component == ComponentFleet || report.Identity.MachineID == "" || !hasRequiredComponentChecks(report) {
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
				schemaCompatible = false
			}
		} else if report.Component == ComponentServer {
			schemaCompatible = false
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
		fleetBoolCheck(schemaCompatible && len(schemas) <= 1, "schema_skew", "complete_server_update"),
		fleetBoolCheck(supportedFleetEdges(releases, policy.SupportedFrom), "upgrade_edges", "follow_supported_upgrade_edge"),
		fleetBoolCheck(pluginOK && len(plugins) <= 1, "plugin_skew", "install_matching_plugin"),
		fleetBoolCheck(skillOK && len(skills) <= 1, "skill_set_skew", "install_matching_skill_set"),
	}
	return New(ComponentFleet, Identity{CatalogSequence: policy.CatalogSequence}, checks)
}

func hasRequiredComponentChecks(report Report) bool {
	required, ok := requiredComponentCheckCodes[report.Component]
	if !ok || len(required) == 0 || len(report.Checks) < len(required) {
		return false
	}
	present := make(map[string]struct{}, len(report.Checks))
	for _, check := range report.Checks {
		present[check.Code] = struct{}{}
	}
	for _, code := range required {
		if _, ok := present[code]; !ok {
			return false
		}
	}
	return true
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
