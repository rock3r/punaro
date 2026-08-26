package main

import (
	"context"

	"github.com/rock3r/punaro/internal/bootstrap"
	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
)

func init() {
	// Production service, bootstrap, bootstrap-release, and client-launcher
	// inspection launch the current executable as deadline-isolated helpers.
	// Unit tests call the direct implementations so the Go test binary cannot
	// recursively launch itself.
	adapterDoctorServiceProbe = func(ctx context.Context, _ adapterConfig) (serviceDoctorResult, error) {
		return inspectAdapterService(ctx), nil
	}
	adapterDoctorBootstrapReleaseProbe = func(ctx context.Context) string {
		return inspectAdapterBootstrapRelease(ctx, defaultAdapterBootstrapExecutable())
	}
	adapterDoctorBootstrapProbe = func(ctx context.Context, directory, bootstrapRelease string) (punarodiagnostic.Report, error) {
		return bootstrap.Doctor(ctx, bootstrap.DoctorRequest{Directory: directory, BootstrapRelease: bootstrapRelease})
	}
	adapterDoctorClientLauncherProbe = func(ctx context.Context) (bool, error) {
		return clientComponentLaunchersMatch(ctx, defaultAdapterBinDirectory()), nil
	}
}
