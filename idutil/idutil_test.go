package idutil

import (
	"testing"

	"github.com/oklog/ulid/v2"
)

func TestNewID(t *testing.T) {
	t.Parallel()

	actual, err := NewID()
	if err != nil {
		t.Fatalf("NewID() = _, %v; want _, nil", err)
	}

	if _, err := ulid.ParseStrict(actual); err != nil {
		t.Errorf("ulid.ParseStrict(NewID()) = %v; want nil", err)
	}
}
