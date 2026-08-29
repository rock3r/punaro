package main

func init() {
	// Production plugin inspection is child-isolated so stalled storage cannot
	// outlive the doctor deadline. Unit tests call the direct implementation to
	// avoid recursively launching the Go test binary as that child helper.
	adapterDoctorPluginProbe = inspectAdapterPlugin
}
