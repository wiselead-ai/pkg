package passwordutil

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"log"

	"golang.org/x/crypto/argon2"
)

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var defaultParams = params{
	memory:      64 * 1024, // 64 MB
	iterations:  3,
	parallelism: 2,
	saltLength:  16,
	keyLength:   32,
}

type Option func(*params)

// WithCustomParams allows customization of hashing parameters
func WithCustomParams(customParams params) Option {
	return func(p *params) {
		p.memory = customParams.memory
		p.iterations = customParams.iterations
		p.parallelism = customParams.parallelism
		p.saltLength = customParams.saltLength
		p.keyLength = customParams.keyLength
	}
}

func Hash(password string, opts ...Option) ([]byte, error) {
	p := defaultParams
	for _, opt := range opts {
		opt(&p)
	}

	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		return nil, err
	}

	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Combine salt and hash for storage
	combined := append(salt, hash...)
	return combined, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Verify compares a password against a hash using the same parameters
func Verify(password string, hash []byte, opts ...Option) (bool, error) {
	p := defaultParams
	for _, opt := range opts {
		opt(&p)
	}

	if uint32(len(hash)) < p.saltLength+p.keyLength {
		log.Println("Hash length is insufficient")
		return false, errors.New("hash length is insufficient")
	}

	salt := hash[:p.saltLength]
	storedHash := hash[p.saltLength:]

	computedHash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Log for debugging
	log.Printf("Stored Hash: %x", storedHash)
	log.Printf("Computed Hash: %x", computedHash)

	if subtle.ConstantTimeCompare(storedHash, computedHash) == 1 {
		return true, nil
	}
	log.Println("Password verification failed")
	return false, nil
}
