package diagnostic

// FleetConfigChecks builds content-free doctor checks for fleet-config convergence.
func FleetConfigChecks(desiredDigest string, clientStates []string) []Check {
	checks := []Check{
		boolCheck("fleet_config_desired", desiredDigest != "", "publish_fleet_config"),
	}
	stale, failed, drifted, unsupported := false, false, false, false
	for _, state := range clientStates {
		switch state {
		case "failed":
			failed = true
		case "drifted":
			drifted = true
		case "unsupported":
			unsupported = true
		case "offline":
			stale = true
		}
	}
	checks = append(checks,
		boolCheck("fleet_config_client_stale", !stale, "reconnect_fleet_client"),
		boolCheck("fleet_config_failed", !failed, "retry_fleet_apply"),
		boolCheck("fleet_config_drifted", !drifted, "replace_fleet_prefix"),
		boolCheck("fleet_config_unsupported", !unsupported, "disable_unsupported_harness"),
	)
	return checks
}

func boolCheck(code string, ok bool, remediation string) Check {
	if ok {
		return Check{Code: code, Status: StatusPass, Required: true}
	}
	return Check{Code: code, Status: StatusFail, Required: true, Remediation: remediation}
}
