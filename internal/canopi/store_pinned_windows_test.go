//go:build windows

package canopi

import (
	"math"
	"testing"
)

func TestCheckedWindowsInformationLength(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		length int
		want   uint32
	}{
		{length: 0, want: 0},
		{length: 1, want: 1},
		{length: math.MaxUint32, want: math.MaxUint32},
	} {
		got, err := checkedWindowsInformationLength(testCase.length)
		if err != nil {
			t.Fatalf("checkedWindowsInformationLength(%d): %v", testCase.length, err)
		}
		if got != testCase.want {
			t.Fatalf("checkedWindowsInformationLength(%d) = %d, want %d", testCase.length, got, testCase.want)
		}
	}
}

func TestCheckedWindowsInformationLengthRejectsOverflow(t *testing.T) {
	t.Parallel()

	if uint64(^uint(0)) <= math.MaxUint32 {
		t.Skip("int cannot represent a uint32 overflow on this platform")
	}
	if _, err := checkedWindowsInformationLength(int(uint64(math.MaxUint32) + 1)); err == nil {
		t.Fatal("checkedWindowsInformationLength accepted a uint32 overflow")
	}
}
