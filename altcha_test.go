package altcha

import (
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestCreateChallenge(t *testing.T) {
	t.Run("ChallengeWithParams", func(t *testing.T) {
		expires := time.Now().Add(10 * time.Minute)
		options := ChallengeOptions{
			HMACKey:    "test-key",
			SaltLength: 16,
			Algorithm:  SHA256,
			Expires:    &expires,
			Params:     url.Values{"foo": {"bar"}},
		}

		challenge, err := CreateChallenge(options)
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}

		if challenge.Algorithm != string(SHA256) {
			t.Errorf("CreateChallenge() Algorithm = %v, want %v", challenge.Algorithm, SHA256)
		}
		if challenge.Salt == "" {
			t.Error("CreateChallenge() Salt should not be empty")
		}
		if challenge.Signature == "" {
			t.Error("CreateChallenge() Signature should not be empty")
		}
	})

	// Challenge without params with possible null pointer panic
	t.Run("ChallengeWithoutParams", func(t *testing.T) {
		expires := time.Now().Add(10 * time.Minute)
		options := ChallengeOptions{
			HMACKey:    "test-key",
			SaltLength: 16,
			Algorithm:  SHA256,
			Expires:    &expires,
		}

		challenge, err := CreateChallenge(options)
		if err != nil {
			t.Fatalf("CreateChallenge() error = %v", err)
		}

		if challenge.Algorithm != string(SHA256) {
			t.Errorf("CreateChallenge() Algorithm = %v, want %v", challenge.Algorithm, SHA256)
		}
		if challenge.Salt == "" {
			t.Error("CreateChallenge() Salt should not be empty")
		}
		if challenge.Signature == "" {
			t.Error("CreateChallenge() Signature should not be empty")
		}
	})
}

func TestVerifySolution(t *testing.T) {
	expires := time.Now().Add(10 * time.Minute)
	options := ChallengeOptions{
		HMACKey:    "test-key",
		SaltLength: 16,
		Algorithm:  SHA256,
		Expires:    &expires,
		Number:     10,
		Params:     url.Values{"foo": {"bar"}},
	}

	challenge, err := CreateChallenge(options)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}

	payload := Payload{
		Algorithm: challenge.Algorithm,
		Challenge: challenge.Challenge,
		Number:    10,
		Salt:      challenge.Salt,
		Signature: challenge.Signature,
	}

	valid, err := VerifySolution(payload, "test-key", true)
	if err != nil {
		t.Fatalf("VerifySolution() error = %v", err)
	}
	if !valid {
		t.Error("VerifySolution() should return true for valid solution")
	}
}

func TestExtractParams(t *testing.T) {
	payload := Payload{
		Salt: "abc123?foo=bar&baz=qux",
	}

	expectedParams := url.Values{
		"foo": {"bar"},
		"baz": {"qux"},
	}

	params := ExtractParams(payload)
	if !reflect.DeepEqual(params, expectedParams) {
		t.Errorf("ExtractParams() = %v, want %v", params, expectedParams)
	}
}

func TestVerifyFieldsHash(t *testing.T) {
	formData := map[string][]string{
		"name":  {"John Doe"},
		"email": {"john@example.com"},
	}

	fields := []string{"name", "email"}
	expectedHash, _ := hashHex(SHA256, "John Doe\njohn@example.com")

	valid, err := VerifyFieldsHash(formData, fields, expectedHash, SHA256)
	if err != nil {
		t.Fatalf("VerifyFieldsHash() error = %v", err)
	}
	if !valid {
		t.Error("VerifyFieldsHash() should return true for valid fields hash")
	}
}

func TestVerifyServerSignature(t *testing.T) {
	// Valid signature test case
	t.Run("ValidSignature", func(t *testing.T) {
		verificationData := "expire=" + strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10) +
			"&fields=field1,field2&reasons=reason1,reason2&score=3&time=" +
			strconv.FormatInt(time.Now().Unix(), 10) + "&verified=true"
		hash, _ := hash(SHA256, []byte(verificationData))
		expectedSignature, err := hmacHex(SHA256, hash, "test-key")
		if err != nil {
			t.Fatalf("hmacHex() error = %v", err)
		}
		payload := ServerSignaturePayload{
			Algorithm:        SHA256,
			VerificationData: verificationData,
			Signature:        expectedSignature,
			Verified:         true,
		}

		isValid, data, err := VerifyServerSignature(payload, "test-key")
		if err != nil {
			t.Fatalf("VerifyServerSignature() error = %v", err)
		}
		if !isValid {
			t.Error("VerifyServerSignature() should return true for valid signature")
		}
		if data.Expire <= 0 || len(data.Fields) == 0 || len(data.Reasons) == 0 || data.Score == 0 || data.Time <= 0 || !data.Verified {
			t.Errorf("VerifyServerSignature() verificationData = %v, want correct data", data)
		}
	})

	// Invalid signature test case
	t.Run("InvalidSignature", func(t *testing.T) {
		verificationData := "expire=" + strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10) +
			"&fields=field1,field2&reasons=reason1,reason2&score=3&time=" +
			strconv.FormatInt(time.Now().Unix(), 10) + "&verified=true"
		payload := ServerSignaturePayload{
			Algorithm:        SHA256,
			VerificationData: verificationData,
			Signature:        "invalidSignature",
			Verified:         true,
		}

		isValid, _, err := VerifyServerSignature(payload, "test-key")
		if err != nil {
			t.Fatalf("VerifyServerSignature() error = %v", err)
		}
		if isValid {
			t.Error("VerifyServerSignature() should return false for invalid signature")
		}
	})

	// Expired payload test case
	t.Run("ExpiredPayload", func(t *testing.T) {
		verificationData := "expire=" + strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10) +
			"&fields=field1,field2&reasons=reason1,reason2&score=3&time=" +
			strconv.FormatInt(time.Now().Unix(), 10) + "&verified=true"
		expectedSignature, err := hmacHex(SHA256, []byte(verificationData), "test-key")
		if err != nil {
			t.Fatalf("hmacHex() error = %v", err)
		}
		payload := ServerSignaturePayload{
			Algorithm:        SHA256,
			VerificationData: verificationData,
			Signature:        expectedSignature,
			Verified:         true,
		}

		isValid, _, err := VerifyServerSignature(payload, "test-key")
		if err != nil {
			t.Fatalf("VerifyServerSignature() error = %v", err)
		}
		if isValid {
			t.Error("VerifyServerSignature() should return false for expired payload")
		}
	})
}

func TestSolveChallenge(t *testing.T) {
	tests := []struct {
		name        string
		challenge   string
		salt        string
		algorithm   string
		max         int
		start       int
		expected    *Solution
		expectError bool
	}{
		{
			name:      "successful solution with SHA-256",
			challenge: "c2fc6c6adf8ba0f575a35f48df52c0968a3dcd3c577c2769dc2f1035943b975e", // Example hash for "salt123"
			salt:      "salt",
			algorithm: "SHA-256",
			max:       100000,
			start:     0,
			expected: &Solution{
				Number: 123,
				Took:   0, // Time will vary, so this is not strictly tested
			},
			expectError: false,
		},
		{
			name:        "unsuccessful solution",
			challenge:   "invalidhash",
			salt:        "salt",
			algorithm:   "SHA-256",
			max:         1000,
			start:       0,
			expected:    nil,
			expectError: false,
		},
		{
			name:        "unsupported algorithm",
			challenge:   "c2fc6c6adf8ba0f575a35f48df52c0968a3dcd3c577c2769dc2f1035943b975e",
			salt:        "salt",
			algorithm:   "SHA-999", // Unsupported algorithm
			max:         100000,
			start:       0,
			expected:    nil,
			expectError: true,
		},
		{
			name:        "cancellation test",
			challenge:   "751a512dc299d1193434e6d7065f64d90e5bef33ab45ab841fb7231ecef3fa5a", // Example hash for "salt1234567"
			salt:        "salt",
			algorithm:   "SHA-256",
			max:         100000,
			start:       0,
			expected:    nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopChan := make(chan struct{})
			defer close(stopChan)

			if tt.name == "cancellation test" {
				go func() {
					time.Sleep(10 * time.Millisecond)
					_, ok := <-stopChan
					if ok {
						close(stopChan)
					}
				}()
			}

			startTime := time.Now()
			got, err := SolveChallenge(tt.challenge, tt.salt, Algorithm(tt.algorithm), tt.max, tt.start, stopChan)
			duration := time.Since(startTime)

			if (err != nil) != tt.expectError {
				t.Errorf("solveChallenge() error = %v, expectError %v", err, tt.expectError)
				return
			}
			if tt.expectError {
				return
			}

			if got != nil {
				if got.Number != tt.expected.Number {
					t.Errorf("solveChallenge() = %v, want %v", got.Number, tt.expected.Number)
				}
				if duration < got.Took {
					t.Errorf("solveChallenge() took less time than expected, got %v, expected %v", duration, got.Took)
				}
			} else if tt.expected != nil {
				t.Errorf("solveChallenge() = %v, want %v", got, tt.expected)
			}
		})
	}
}
