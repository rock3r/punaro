package main

import "context"

func init() {
	// Production reads are child-isolated so a stalled mount cannot outlive the
	// doctor deadline. Unit tests use the direct implementation to avoid
	// recursively launching the Go test binary as that child helper.
	serverDoctorDSNRead = directServerDoctorDSN
	serverDoctorPathCheck = directServerDoctorPaths
	serverDoctorStorageCheck = directServerDoctorStorage
	serverDoctorBackupCheck = directServerDoctorBackups
	serverDoctorFileDigest = directServerDoctorFileDigest
	serverDoctorGatewayServiceCheck = directServerDoctorGatewayService
	serverDoctorProfileLoad = loadServerDoctorProfile
	serverDoctorRecoveryReceiptCheck = func(_ context.Context, request serverDoctorRecoveryReceiptRequest) knownDoctorBool {
		return inspectServerDoctorRecoveryReceipt(request)
	}
}
