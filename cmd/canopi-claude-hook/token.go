package main

import (
	"github.com/rock3r/punaro/internal/canopicredential"
)

func readProtectedToken(path string) ([]byte, error) {
	token, err := canopicredential.ReadToken(path)
	if err != nil {
		return nil, err
	}
	return []byte(token), nil
}
