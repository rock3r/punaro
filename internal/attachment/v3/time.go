package v3

import (
	"errors"
	"math"
)

// unixSeconds is the only conversion from protocol uint64 time to the signed
// SQLite Unix-second representation. Protocol decoders reject values outside
// this range before persistence, but this helper keeps every database boundary
// mechanically checked as well.
func unixSeconds(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, errors.New("unrepresentable Unix timestamp")
	}
	return int64(value), nil
}
