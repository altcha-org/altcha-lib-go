package altcha

import (
	"testing"
)

func TestDeriveKeyPBKDF2(t *testing.T) {
	deriveKey := DeriveKeyPBKDF2()
	params := ChallengeParameters{
		Algorithm: "PBKDF2/SHA-256",
		Cost:      1000,
		KeyLength: 32,
	}
	key, err := deriveKey(params, []byte("salt"), []byte("password"))
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2() error = %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected key length 32, got %d", len(key))
	}

	// Same inputs should produce same output
	key2, _ := deriveKey(params, []byte("salt"), []byte("password"))
	if string(key) != string(key2) {
		t.Error("PBKDF2 should be deterministic")
	}

	// Different password should produce different key
	key3, _ := deriveKey(params, []byte("salt"), []byte("different"))
	if string(key) == string(key3) {
		t.Error("different passwords should produce different keys")
	}
}

func TestDeriveKeyPBKDF2SHA512(t *testing.T) {
	deriveKey := DeriveKeyPBKDF2()
	params := ChallengeParameters{
		Algorithm: "PBKDF2/SHA-512",
		Cost:      1000,
		KeyLength: 64,
	}
	key, err := deriveKey(params, []byte("salt"), []byte("password"))
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2(SHA-512) error = %v", err)
	}
	if len(key) != 64 {
		t.Errorf("expected key length 64, got %d", len(key))
	}
}

func TestDeriveKeyScrypt(t *testing.T) {
	deriveKey := DeriveKeyScrypt()
	params := ChallengeParameters{
		Algorithm:   "Scrypt",
		Cost:        1024,
		MemoryCost:  8,
		Parallelism: 1,
		KeyLength:   32,
	}
	key, err := deriveKey(params, []byte("salt"), []byte("password"))
	if err != nil {
		t.Fatalf("DeriveKeyScrypt() error = %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected key length 32, got %d", len(key))
	}

	// Deterministic
	key2, _ := deriveKey(params, []byte("salt"), []byte("password"))
	if string(key) != string(key2) {
		t.Error("Scrypt should be deterministic")
	}
}

func TestDeriveKeyArgon2id(t *testing.T) {
	deriveKey := DeriveKeyArgon2id()
	params := ChallengeParameters{
		Algorithm:   "Argon2id",
		Cost:        1,
		MemoryCost:  1024,
		Parallelism: 1,
		KeyLength:   32,
	}
	key, err := deriveKey(params, []byte("saltsalt"), []byte("password"))
	if err != nil {
		t.Fatalf("DeriveKeyArgon2id() error = %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected key length 32, got %d", len(key))
	}

	// Deterministic
	key2, _ := deriveKey(params, []byte("saltsalt"), []byte("password"))
	if string(key) != string(key2) {
		t.Error("Argon2id should be deterministic")
	}
}

func TestDeriveKeySHA(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		keyLength int
	}{
		{"SHA-256", "SHA-256", 32},
		{"SHA-384", "SHA-384", 32},
		{"SHA-512", "SHA-512", 32},
		{"default", "", 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deriveKey := DeriveKeySHA()
			params := ChallengeParameters{
				Algorithm: tt.algorithm,
				Cost:      10,
				KeyLength: tt.keyLength,
			}
			key, err := deriveKey(params, []byte("salt"), []byte("password"))
			if err != nil {
				t.Fatalf("DeriveKeySHA() error = %v", err)
			}
			if len(key) != tt.keyLength {
				t.Errorf("expected key length %d, got %d", tt.keyLength, len(key))
			}
			// Deterministic
			key2, _ := deriveKey(params, []byte("salt"), []byte("password"))
			if string(key) != string(key2) {
				t.Error("SHA should be deterministic")
			}
			// Different password produces different key
			key3, _ := deriveKey(params, []byte("salt"), []byte("different"))
			if string(key) == string(key3) {
				t.Error("different passwords should produce different keys")
			}
		})
	}
}

func TestDeriveKeySHACostAffectsOutput(t *testing.T) {
	deriveKey := DeriveKeySHA()
	params1 := ChallengeParameters{Algorithm: "SHA-256", Cost: 1, KeyLength: 32}
	params2 := ChallengeParameters{Algorithm: "SHA-256", Cost: 10, KeyLength: 32}
	key1, _ := deriveKey(params1, []byte("salt"), []byte("password"))
	key2, _ := deriveKey(params2, []byte("salt"), []byte("password"))
	if string(key1) == string(key2) {
		t.Error("different cost values should produce different keys")
	}
}

func TestRoundTripSHA(t *testing.T) {
	deriveKey := DeriveKeySHA()
	counter := 5
	challenge, err := CreateChallenge(CreateChallengeOptions{
		Algorithm:           "SHA-256",
		HMACSignatureSecret: "test-secret",
		Counter:             &counter,
		DeriveKey:           deriveKey,
		Cost:                100,
		KeyLength:           16,
	})
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}

	solution, err := SolveChallenge(SolveChallengeOptions{
		Challenge: challenge,
		DeriveKey: deriveKey,
	})
	if err != nil {
		t.Fatalf("SolveChallenge() error = %v", err)
	}
	if solution == nil {
		t.Fatal("SolveChallenge() returned nil")
	}
	if solution.Counter != counter {
		t.Errorf("expected counter %d, got %d", counter, solution.Counter)
	}

	result, err := VerifySolution(VerifySolutionOptions{
		Challenge:           challenge,
		Solution:            *solution,
		DeriveKey:           deriveKey,
		HMACSignatureSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("VerifySolution() error = %v", err)
	}
	if !result.Verified {
		t.Error("should be verified")
	}
}

func TestRoundTripScrypt(t *testing.T) {
	deriveKey := DeriveKeyScrypt()
	counter := 3
	challenge, err := CreateChallenge(CreateChallengeOptions{
		Algorithm:           "Scrypt",
		HMACSignatureSecret: "test-secret",
		Counter:             &counter,
		DeriveKey:           deriveKey,
		Cost:                1024,
		MemoryCost:          8,
		Parallelism:         1,
		KeyLength:           16,
	})
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}

	solution, err := SolveChallenge(SolveChallengeOptions{
		Challenge: challenge,
		DeriveKey: deriveKey,
	})
	if err != nil {
		t.Fatalf("SolveChallenge() error = %v", err)
	}
	if solution == nil {
		t.Fatal("SolveChallenge() returned nil")
	}
	if solution.Counter != counter {
		t.Errorf("expected counter %d, got %d", counter, solution.Counter)
	}

	result, err := VerifySolution(VerifySolutionOptions{
		Challenge:           challenge,
		Solution:            *solution,
		DeriveKey:           deriveKey,
		HMACSignatureSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("VerifySolution() error = %v", err)
	}
	if !result.Verified {
		t.Error("should be verified")
	}
}

func TestRoundTripArgon2id(t *testing.T) {
	deriveKey := DeriveKeyArgon2id()
	counter := 2
	challenge, err := CreateChallenge(CreateChallengeOptions{
		Algorithm:           "Argon2id",
		HMACSignatureSecret: "test-secret",
		Counter:             &counter,
		DeriveKey:           deriveKey,
		Cost:                1,
		MemoryCost:          1024,
		Parallelism:         1,
		KeyLength:           16,
	})
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}

	solution, err := SolveChallenge(SolveChallengeOptions{
		Challenge: challenge,
		DeriveKey: deriveKey,
	})
	if err != nil {
		t.Fatalf("SolveChallenge() error = %v", err)
	}
	if solution == nil {
		t.Fatal("SolveChallenge() returned nil")
	}
	if solution.Counter != counter {
		t.Errorf("expected counter %d, got %d", counter, solution.Counter)
	}

	result, err := VerifySolution(VerifySolutionOptions{
		Challenge:           challenge,
		Solution:            *solution,
		DeriveKey:           deriveKey,
		HMACSignatureSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("VerifySolution() error = %v", err)
	}
	if !result.Verified {
		t.Error("should be verified")
	}
}
