//go:build !unix && !windows

package fleetconfig

import "errors"

func createAliasLink(string, string) error {
	return errors.New("aliases are unsupported on this platform")
}
