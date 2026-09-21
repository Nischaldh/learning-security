package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"golang.org/x/crypto/argon2"
	"unicode/utf8"
)

const (
	MaxLength = 128

	argon2Memory      = 19 * 1024 // 19 MiB, in KiB
	argon2Iterations  = 2
	argon2Parallelism = 1
	argon2KeyLength   = 32
	argon2SaltLength  = 16
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	// passwordHash := sha256.Sum256([]byte(password))
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		argon2Iterations,
		argon2Memory,
		argon2Parallelism,
		argon2KeyLength,
	)

	passwordHash := argon2idHash{
		version:     argon2.Version,
		memoryKiB:   argon2Memory,
		iterations:  argon2Iterations,
		parallelism: argon2Parallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}
	return encodeArgon2idHash(passwordHash), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	if len(encodedHash) == sha256.Size*2 {

		expectedHash, ok := decodeLegacyHash(encodedHash)
		if !ok {
			return false
		}
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}
	argon2idHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if argon2idHash.version != argon2.Version {
		return false
	}
	actualKey := argon2.IDKey(
		[]byte(password),
		argon2idHash.salt,
		argon2idHash.iterations,
		argon2idHash.memoryKiB,
		argon2idHash.parallelism,
		uint32(len(argon2idHash.derivedKey)),
	)
	return subtle.ConstantTimeCompare(actualKey, argon2idHash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if len(encodedHash) == sha256.Size*2 {
		return true
	}
	argon2idHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if argon2idHash.version != argon2.Version || argon2idHash.memoryKiB != argon2Memory || argon2idHash.iterations != argon2Iterations || argon2idHash.parallelism != argon2Parallelism || len(argon2idHash.derivedKey) != argon2KeyLength {
		return true
	}

	return false
}
