package idutil

import (
	"fmt"
	"time"

	"math/rand"

	"github.com/oklog/ulid/v2"
)

// NewID is a helper function to generate a new ULID string.
func NewID() (string, error) {
	id, err := ulid.New(
		ulid.Timestamp(time.Now()),
		rand.New(rand.NewSource(time.Now().UnixNano())),
	)
	if err != nil {
		return "", fmt.Errorf("could not generate new ULID: %w", err)
	}
	return id.String(), nil
}
