package adapter

import "github.com/rock3r/punaro/internal/fleetconfig"

// ReconcileFleet atomically applies a validated tree under root, preserving trailers.
func ReconcileFleet(root string, tree fleetconfig.Tree, existing map[string][]byte, lastPrefixDigests map[string]string, digest string) (map[string]fleetconfig.TrailerResult, error) {
	files, trailers, err := fleetconfig.PrepareApply(tree, existing, lastPrefixDigests)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return trailers, nil
	}
	if err := fleetconfig.PublishTree(root, files, digest); err != nil {
		_ = fleetconfig.RestoreLastGood(root)
		return trailers, err
	}
	return trailers, nil
}
