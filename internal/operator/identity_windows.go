//go:build windows

package operator

import "errors"

func runtimeIdentity() (string, string, error) {
	return "", "", errors.New("the server operator wrapper requires a Unix host")
}
