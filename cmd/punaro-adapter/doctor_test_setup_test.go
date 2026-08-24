package main

import (
	"context"

	"github.com/rock3r/punaro/internal/bootstrap"
	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
)

func init() {
	adapterDoctorBootstrapProbe = func(ctx context.Context, directory, bootstrapRelease string) (punarodiagnostic.Report, error) {
		return bootstrap.Doctor(ctx, bootstrap.DoctorRequest{Directory: directory, BootstrapRelease: bootstrapRelease})
	}
}
