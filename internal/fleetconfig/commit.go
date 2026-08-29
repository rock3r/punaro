package fleetconfig

import (
	"errors"
	"regexp"
)

var commitIDPattern = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)

// ParseCommitID accepts a full immutable Git commit identity only.
func ParseCommitID(id string) (string, error) {
	if !commitIDPattern.MatchString(id) {
		return "", errors.New("commit identity must be a full lowercase Git object name")
	}
	return id, nil
}
