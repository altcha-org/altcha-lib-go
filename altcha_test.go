package altcha

import (
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func TestCreateChallengeV2(t *testing.T) {
	t.Run("DefaultOptions", func(t *testing.T) {
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:           "PBKDF2/SHA-256",
			HMACSignatureSecret: "test-secret",
			Cost:                1000,
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}
		if challenge.Parameters.Algorithm != "PBKDF2/SHA-256" {
			t.Errorf("expected algorithm PBKDF2/SHA-256, got %s", challenge.Parameters.Algorithm)
		}
		if challenge.Parameters.KeyLength != defaultKeyLength {
			t.Errorf("expected keyLength %d, got %d", defaultKeyLength, challenge.Parameters.KeyLength)
		}
		if challenge.Parameters.Nonce == "" {
			t.Error("nonce should not be empty")
		}
		if challenge.Parameters.Salt == "" {
			t.Error("salt should not be empty")
		}
		if challenge.Parameters.KeyPrefix == "" {
			t.Error("keyPrefix should not be empty")
		}
		if challenge.Signature == "" {
			t.Error("signature should not be empty")
		}
	})

	t.Run("WithDeterministicCounter", func(t *testing.T) {
		counter := 42
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:           "PBKDF2/SHA-256",
			HMACSignatureSecret: "test-secret",
			Counter:             &counter,
			DeriveKey:           DeriveKeyPBKDF2(),
			Cost:                1000,
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}
		// With a deterministic counter, the keyPrefix should be set to the full derived key
		if challenge.Parameters.KeyPrefix == "" {
			t.Error("keyPrefix should be set when using deterministic counter")
		}
	})

	t.Run("WithExpiresAt", func(t *testing.T) {
		expires := time.Now().Add(10 * time.Minute)
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:           "PBKDF2/SHA-256",
			HMACSignatureSecret: "test-secret",
			ExpiresAt:           &expires,
			Cost:                1000,
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}
		if challenge.Parameters.ExpiresAt != expires.Unix() {
			t.Errorf("expected expiresAt %d, got %d", expires.Unix(), challenge.Parameters.ExpiresAt)
		}
	})

	t.Run("WithKeySignature", func(t *testing.T) {
		counter := 5
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:              "PBKDF2/SHA-256",
			HMACSignatureSecret:    "test-secret",
			HMACKeySignatureSecret: "key-secret",
			Counter:                &counter,
			DeriveKey:              DeriveKeyPBKDF2(),
			Cost:                   1000,
			KeyLength:              16,
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}
		if challenge.Parameters.KeySignature == "" {
			t.Error("keySignature should not be empty when counter and DeriveKey are provided")
		}
		if challenge.Signature == "" {
			t.Error("signature should not be empty")
		}
	})

	t.Run("WithData", func(t *testing.T) {
		data := map[string]interface{}{"foo": "bar", "count": float64(42)}
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:           "PBKDF2/SHA-256",
			HMACSignatureSecret: "test-secret",
			Data:                data,
			Cost:                1000,
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}
		if challenge.Parameters.Data["foo"] != "bar" {
			t.Error("data should contain foo=bar")
		}
	})
}

func TestSolveChallengeV2(t *testing.T) {
	t.Run("RoundTripPBKDF2", func(t *testing.T) {
		deriveKey := DeriveKeyPBKDF2()
		counter := 5
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:           "PBKDF2/SHA-256",
			HMACSignatureSecret: "test-secret",
			Counter:             &counter,
			DeriveKey:           deriveKey,
			Cost:                1000,
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
			t.Fatal("SolveChallenge() returned nil solution")
		}
		if solution.Counter != counter {
			t.Errorf("expected counter %d, got %d", counter, solution.Counter)
		}
		if solution.DerivedKey == "" {
			t.Error("derivedKey should not be empty")
		}

		// Verify the solution
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
			t.Error("VerifySolution() should return verified=true")
		}
		if result.InvalidSignature != nil && *result.InvalidSignature {
			t.Error("signature should be valid")
		}
		if result.InvalidSolution != nil && *result.InvalidSolution {
			t.Error("solution should be valid")
		}
	})

	t.Run("WithCancellation", func(t *testing.T) {
		deriveKey := DeriveKeyPBKDF2()
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm: "PBKDF2/SHA-256",
			Cost:      1000,
			KeyLength: 16,
			KeyPrefix: "ffffffffffffffff", // very unlikely prefix
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}

		stopChan := make(chan struct{})
		go func() {
			time.Sleep(50 * time.Millisecond)
			close(stopChan)
		}()

		solution, err := SolveChallenge(SolveChallengeOptions{
			Challenge: challenge,
			DeriveKey: deriveKey,
			StopChan:  stopChan,
		})
		if err != nil {
			t.Fatalf("SolveChallenge() error = %v", err)
		}
		if solution != nil {
			t.Error("SolveChallenge() should return nil when cancelled")
		}
	})
}

func TestVerifySolutionV2(t *testing.T) {
	t.Run("ExpiredChallenge", func(t *testing.T) {
		expired := time.Now().Add(-10 * time.Minute)
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:           "PBKDF2/SHA-256",
			HMACSignatureSecret: "test-secret",
			ExpiresAt:           &expired,
			Cost:                1000,
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}

		result, err := VerifySolution(VerifySolutionOptions{
			Challenge:           challenge,
			Solution:            Solution{Counter: 0, DerivedKey: "abc"},
			HMACSignatureSecret: "test-secret",
			DeriveKey:           DeriveKeyPBKDF2(),
		})
		if err != nil {
			t.Fatalf("VerifySolution() error = %v", err)
		}
		if !result.Expired {
			t.Error("expected expired=true")
		}
		if result.Verified {
			t.Error("expired challenge should not be verified")
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:           "PBKDF2/SHA-256",
			HMACSignatureSecret: "test-secret",
			Cost:                1000,
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}

		// Tamper with the signature
		challenge.Signature = "invalid"

		result, err := VerifySolution(VerifySolutionOptions{
			Challenge:           challenge,
			Solution:            Solution{Counter: 0, DerivedKey: "abc"},
			HMACSignatureSecret: "test-secret",
			DeriveKey:           DeriveKeyPBKDF2(),
		})
		if err != nil {
			t.Fatalf("VerifySolution() error = %v", err)
		}
		if result.Verified {
			t.Error("tampered signature should not verify")
		}
		if result.InvalidSignature == nil || !*result.InvalidSignature {
			t.Error("expected invalidSignature=true")
		}
	})

	t.Run("InvalidSolution", func(t *testing.T) {
		deriveKey := DeriveKeyPBKDF2()
		counter := 5
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:           "PBKDF2/SHA-256",
			HMACSignatureSecret: "test-secret",
			Counter:             &counter,
			DeriveKey:           deriveKey,
			Cost:                1000,
			KeyLength:           16,
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}

		// Provide wrong solution
		result, err := VerifySolution(VerifySolutionOptions{
			Challenge:           challenge,
			Solution:            Solution{Counter: 999, DerivedKey: "0000"},
			DeriveKey:           deriveKey,
			HMACSignatureSecret: "test-secret",
		})
		if err != nil {
			t.Fatalf("VerifySolution() error = %v", err)
		}
		if result.Verified {
			t.Error("wrong solution should not verify")
		}
		if result.InvalidSolution == nil || !*result.InvalidSolution {
			t.Error("expected invalidSolution=true")
		}
	})

	t.Run("KeySignatureFastPath", func(t *testing.T) {
		deriveKey := DeriveKeyPBKDF2()
		counter := 5
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:              "PBKDF2/SHA-256",
			HMACSignatureSecret:    "test-secret",
			HMACKeySignatureSecret: "key-secret",
			Counter:                &counter,
			DeriveKey:              deriveKey,
			Cost:                   1000,
			KeyLength:              16,
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}
		if challenge.Parameters.KeySignature == "" {
			t.Fatal("keySignature should be set")
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

		result, err := VerifySolution(VerifySolutionOptions{
			Challenge:              challenge,
			Solution:               *solution,
			HMACSignatureSecret:    "test-secret",
			HMACKeySignatureSecret: "key-secret",
		})
		if err != nil {
			t.Fatalf("VerifySolution() error = %v", err)
		}
		if !result.Verified {
			t.Error("key signature fast path should verify")
		}
		if result.InvalidSolution != nil && *result.InvalidSolution {
			t.Error("solution should be valid")
		}
	})

	t.Run("SignatureOnlyVerification", func(t *testing.T) {
		challenge, err := CreateChallenge(CreateChallengeOptions{
			Algorithm:           "PBKDF2/SHA-256",
			HMACSignatureSecret: "test-secret",
			Cost:                1000,
		})
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}

		// Verify with signature only, no DeriveKey
		result, err := VerifySolution(VerifySolutionOptions{
			Challenge:           challenge,
			Solution:            Solution{},
			HMACSignatureSecret: "test-secret",
		})
		if err != nil {
			t.Fatalf("VerifySolution() error = %v", err)
		}
		if !result.Verified {
			t.Error("signature-only verification should pass")
		}
		if result.InvalidSolution != nil {
			t.Error("invalidSolution should be nil when DeriveKey is not provided")
		}
	})
}

func TestPasswordWithCounter(t *testing.T) {
	result := passwordWithCounter([]byte("nonce"), 1)
	expected := append([]byte("nonce"), 0, 0, 0, 1)
	if string(result) != string(expected) {
		t.Errorf("got %v, want %v", result, expected)
	}

	result = passwordWithCounter([]byte("nonce"), 256)
	expected = append([]byte("nonce"), 0, 0, 1, 0)
	if string(result) != string(expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}

func TestCanonicalJSON(t *testing.T) {
	t.Run("SortedKeys", func(t *testing.T) {
		m := map[string]interface{}{
			"z": "last",
			"a": "first",
			"m": "middle",
		}
		result, err := canonicalJSON(m)
		if err != nil {
			t.Fatalf("canonicalJSON() error = %v", err)
		}
		expected := `{"a":"first","m":"middle","z":"last"}`
		if result != expected {
			t.Errorf("got %s, want %s", result, expected)
		}
	})

	t.Run("NestedSortedKeys", func(t *testing.T) {
		m := map[string]interface{}{
			"b": map[string]interface{}{
				"z": 1,
				"a": 2,
			},
			"a": "first",
		}
		result, err := canonicalJSON(m)
		if err != nil {
			t.Fatalf("canonicalJSON() error = %v", err)
		}
		expected := `{"a":"first","b":{"a":2,"z":1}}`
		if result != expected {
			t.Errorf("got %s, want %s", result, expected)
		}
	})
}

func TestBufferStartsWith(t *testing.T) {
	buf, _ := hex.DecodeString("00aabbcc")
	prefix, _ := hex.DecodeString("00aa")
	if !bufferStartsWith(buf, prefix) {
		t.Error("expected true")
	}

	wrongPrefix, _ := hex.DecodeString("ffaa")
	if bufferStartsWith(buf, wrongPrefix) {
		t.Error("expected false")
	}

	if !bufferStartsWith(buf, []byte{}) {
		t.Error("empty prefix should match")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("hello", "hello") {
		t.Error("same strings should be equal")
	}
	if constantTimeEqual("hello", "world") {
		t.Error("different strings should not be equal")
	}
}

func TestVerifyServerSignature(t *testing.T) {
	t.Run("ValidSignature", func(t *testing.T) {
		verificationData := "expire=" + strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10) +
			"&fields=field1,field2&reasons=reason1,reason2&score=3&time=" +
			strconv.FormatInt(time.Now().Unix(), 10) + "&verified=true&abc=123"
		h, _ := hashBytes(SHA256, []byte(verificationData))
		expectedSignature, err := hmacHex(SHA256, h, "test-key")
		if err != nil {
			t.Fatalf("hmacHex() error = %v", err)
		}
		payload := ServerSignaturePayload{
			Algorithm:        SHA256,
			VerificationData: verificationData,
			Signature:        expectedSignature,
			Verified:         true,
		}

		result, err := VerifyServerSignature(payload, "test-key")
		if err != nil {
			t.Fatalf("VerifyServerSignature() error = %v", err)
		}
		if !result.Verified {
			t.Error("should be verified")
		}
		if result.Expired {
			t.Error("should not be expired")
		}
		if result.InvalidSignature {
			t.Error("signature should be valid")
		}
		if result.InvalidSolution {
			t.Error("solution should be valid")
		}
		if result.VerificationData == nil {
			t.Fatal("verificationData should not be nil")
		}
		if result.VerificationData.Extra["abc"] != "123" {
			t.Error("wrong extra parameter value")
		}
		if len(result.VerificationData.Fields) != 2 {
			t.Errorf("expected 2 fields, got %d", len(result.VerificationData.Fields))
		}
		if len(result.VerificationData.Reasons) != 2 {
			t.Errorf("expected 2 reasons, got %d", len(result.VerificationData.Reasons))
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		verificationData := "expire=" + strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10) +
			"&verified=true"
		payload := ServerSignaturePayload{
			Algorithm:        SHA256,
			VerificationData: verificationData,
			Signature:        "invalidSignature",
			Verified:         true,
		}

		result, err := VerifyServerSignature(payload, "test-key")
		if err != nil {
			t.Fatalf("VerifyServerSignature() error = %v", err)
		}
		if result.Verified {
			t.Error("should not be verified")
		}
		if !result.InvalidSignature {
			t.Error("should report invalid signature")
		}
	})

	t.Run("ExpiredPayload", func(t *testing.T) {
		verificationData := "expire=" + strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10) +
			"&verified=true"
		h, _ := hashBytes(SHA256, []byte(verificationData))
		expectedSignature, _ := hmacHex(SHA256, h, "test-key")
		payload := ServerSignaturePayload{
			Algorithm:        SHA256,
			VerificationData: verificationData,
			Signature:        expectedSignature,
			Verified:         true,
		}

		result, err := VerifyServerSignature(payload, "test-key")
		if err != nil {
			t.Fatalf("VerifyServerSignature() error = %v", err)
		}
		if result.Verified {
			t.Error("should not be verified when expired")
		}
		if !result.Expired {
			t.Error("should report expired")
		}
	})

	t.Run("InvalidSolution", func(t *testing.T) {
		verificationData := "expire=" + strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10) +
			"&verified=false"
		h, _ := hashBytes(SHA256, []byte(verificationData))
		expectedSignature, _ := hmacHex(SHA256, h, "test-key")
		payload := ServerSignaturePayload{
			Algorithm:        SHA256,
			VerificationData: verificationData,
			Signature:        expectedSignature,
			Verified:         false,
		}

		result, err := VerifyServerSignature(payload, "test-key")
		if err != nil {
			t.Fatalf("VerifyServerSignature() error = %v", err)
		}
		if result.Verified {
			t.Error("should not be verified")
		}
		if !result.InvalidSolution {
			t.Error("should report invalid solution")
		}
	})
}

func TestVerifyFieldsHash(t *testing.T) {
	formData := map[string][]string{
		"name":  {"John Doe"},
		"email": {"john@example.com"},
	}

	fields := []string{"name", "email"}
	h, _ := hashBytes(SHA256, []byte("John Doe\njohn@example.com"))
	expectedHash := hex.EncodeToString(h)

	valid, err := VerifyFieldsHash(formData, fields, expectedHash, SHA256)
	if err != nil {
		t.Fatalf("VerifyFieldsHash() error = %v", err)
	}
	if !valid {
		t.Error("should return true for valid fields hash")
	}
}
