package passwordutil

import (
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	t.Parallel()

	password := "test-password"

	hashed, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	ok, err := Verify(password, hashed)
	if err != nil || !ok {
		t.Errorf("Verify() with correct password = %v, %v; want true, nil", ok, err)
	}

	ok, err = Verify("wrong-password", hashed)
	if err != nil {
		t.Fatalf("Verify() with wrong password error = %v", err)
	}
	if ok {
		t.Errorf("Verify() with wrong password = %v; want false", ok)
	}
}

func TestWithCustomParams(t *testing.T) {
	custom := params{
		memory:      128 * 1024,
		iterations:  4,
		parallelism: 1,
		saltLength:  32,
		keyLength:   64,
	}

	p := defaultParams
	WithCustomParams(custom)(&p)

	if p.memory != custom.memory ||
		p.iterations != custom.iterations ||
		p.parallelism != custom.parallelism ||
		p.saltLength != custom.saltLength ||
		p.keyLength != custom.keyLength {
		t.Errorf("WithCustomParams() did not correctly set parameters")
	}
}

func TestCustomSaltKeyLength(t *testing.T) {
	t.Parallel()

	password := "custom-test"

	custom := params{
		saltLength: 24,
		keyLength:  48,
	}

	hashed, err := Hash(password, WithCustomParams(custom))
	if err != nil {
		t.Fatalf("Hash() error with custom params = %v", err)
	}

	expectedLen := custom.saltLength + custom.keyLength
	if len(hashed) != int(expectedLen) {
		t.Errorf("Hash length = %d, want %d", len(hashed), expectedLen)
	}
}
