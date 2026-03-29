package altcha

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// DeriveKeySHA returns a DeriveKeyFunc that uses iterated SHA hashing.
// The first iteration hashes concat(salt, password); subsequent iterations
// re-hash the previous result. The number of iterations is controlled by
// Cost (minimum 1). The hash function is selected based on Algorithm:
// "SHA-256" (default), "SHA-384", or "SHA-512".
func DeriveKeySHA() DeriveKeyFunc {
	return func(params ChallengeParameters, salt []byte, password []byte) ([]byte, error) {
		iterations := params.Cost
		if iterations < 1 {
			iterations = 1
		}
		keyLength := params.KeyLength
		if keyLength <= 0 {
			keyLength = 32
		}

		var newHash func() hash.Hash
		switch params.Algorithm {
		case "SHA-512":
			newHash = sha512.New
		case "SHA-384":
			newHash = sha512.New384
		case "SHA-256", "":
			newHash = sha256.New
		default:
			return nil, fmt.Errorf("unsupported SHA algorithm: %s", params.Algorithm)
		}

		var data []byte
		for i := 0; i < iterations; i++ {
			h := newHash()
			if i == 0 {
				h.Write(salt)
				h.Write(password)
			} else {
				h.Write(data)
			}
			data = h.Sum(nil)
		}

		if keyLength > len(data) {
			keyLength = len(data)
		}
		return data[:keyLength], nil
	}
}

// DeriveKeyPBKDF2 returns a DeriveKeyFunc that uses PBKDF2.
// The hash function is selected based on the algorithm field in the parameters:
// "PBKDF2/SHA-256", "PBKDF2/SHA-384", or "PBKDF2/SHA-512".
func DeriveKeyPBKDF2() DeriveKeyFunc {
	return func(params ChallengeParameters, salt []byte, password []byte) ([]byte, error) {
		hashFunc, err := pbkdf2HashFunc(params.Algorithm)
		if err != nil {
			return nil, err
		}
		return pbkdf2.Key(password, salt, params.Cost, params.KeyLength, hashFunc), nil
	}
}

// DeriveKeyScrypt returns a DeriveKeyFunc that uses Scrypt.
// Cost maps to N, MemoryCost maps to r, Parallelism maps to p.
func DeriveKeyScrypt() DeriveKeyFunc {
	return func(params ChallengeParameters, salt []byte, password []byte) ([]byte, error) {
		n := params.Cost
		if n <= 0 {
			n = 16384
		}
		r := params.MemoryCost
		if r <= 0 {
			r = 8
		}
		p := params.Parallelism
		if p <= 0 {
			p = 1
		}
		return scrypt.Key(password, salt, n, r, p, params.KeyLength)
	}
}

// DeriveKeyArgon2id returns a DeriveKeyFunc that uses Argon2id.
// Cost maps to time (iterations), MemoryCost maps to memory in KiB, Parallelism maps to threads.
func DeriveKeyArgon2id() DeriveKeyFunc {
	return func(params ChallengeParameters, salt []byte, password []byte) ([]byte, error) {
		t := uint32(params.Cost)
		if t == 0 {
			t = 1
		}
		m := uint32(params.MemoryCost)
		if m == 0 {
			m = 65536
		}
		p := uint8(params.Parallelism)
		if p == 0 {
			p = 1
		}
		return argon2.IDKey(password, salt, t, m, p, uint32(params.KeyLength)), nil
	}
}

func pbkdf2HashFunc(algorithm string) (func() hash.Hash, error) {
	switch algorithm {
	case "PBKDF2/SHA-256", "":
		return sha256.New, nil
	case "PBKDF2/SHA-384":
		return sha512.New384, nil
	case "PBKDF2/SHA-512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported PBKDF2 hash algorithm: %s", algorithm)
	}
}
