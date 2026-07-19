//go:build !windows

package operator

import (
	"errors"
	"os"
	"strconv"
)

func runtimeIdentity() (string, string, error) {
	if os.Getuid() == 0 || os.Getgid() == 0 {
		return "", "", errors.New("server operator initialization must run as a non-root user")
	}
	return strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid()), nil
}
