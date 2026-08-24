package main

func init() {
	// Production reads are child-isolated so a stalled mount cannot outlive the
	// doctor deadline. Unit tests use the direct implementation to avoid
	// recursively launching the Go test binary as that child helper.
	serverDoctorDSNRead = directServerDoctorDSN
}
