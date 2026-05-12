package altcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Algorithm type definition
type Algorithm string

const (
	SHA1   Algorithm = "SHA-1"
	SHA256 Algorithm = "SHA-256"
	SHA512 Algorithm = "SHA-512"
)

const (
	defaultKeyLength      = 32
	defaultKeyPrefix      = "00"
	defaultKeyPrefixRatio = 2
)

// Challenge represents a v2 challenge with parameters and signature.
type Challenge struct {
	Parameters ChallengeParameters `json:"parameters"`
	Signature  string              `json:"signature,omitempty"`
}

// ChallengeParameters holds the KDF parameters for a v2 challenge.
type ChallengeParameters struct {
	Algorithm    string                 `json:"algorithm"`
	Nonce        string                 `json:"nonce"`
	Salt         string                 `json:"salt"`
	Cost         int                    `json:"cost"`
	KeyLength    int                    `json:"keyLength"`
	KeyPrefix    string                 `json:"keyPrefix"`
	KeySignature string                 `json:"keySignature,omitempty"`
	MemoryCost   int                    `json:"memoryCost,omitempty"`
	Parallelism  int                    `json:"parallelism,omitempty"`
	ExpiresAt    int64                  `json:"expiresAt,omitempty"`
	Data         map[string]interface{} `json:"data,omitempty"`
}

// Solution holds the result of solving a v2 challenge.
type Solution struct {
	Counter    int     `json:"counter"`
	DerivedKey string  `json:"derivedKey"`
	Time       float64 `json:"time,omitempty"`
}

// Payload combines a challenge and its solution for transport.
type Payload struct {
	Challenge Challenge `json:"challenge"`
	Solution  Solution  `json:"solution"`
}

// DeriveKeyFunc is a function that derives a key from KDF parameters.
type DeriveKeyFunc func(params ChallengeParameters, salt []byte, password []byte) ([]byte, error)

// CreateChallengeOptions configures challenge creation.
type CreateChallengeOptions struct {
	Algorithm              string
	Cost                   int
	Counter                *int
	Data                   map[string]interface{}
	DeriveKey              DeriveKeyFunc
	ExpiresAt              *time.Time
	HMACAlgorithm          Algorithm
	HMACKeySignatureSecret string
	HMACSignatureSecret    string
	KeyLength              int
	KeyPrefix              string
	KeyPrefixLength        int
	MemoryCost             int
	Parallelism            int
}

// SolveChallengeOptions configures challenge solving.
type SolveChallengeOptions struct {
	Challenge    Challenge
	CounterStart int
	CounterStep  int
	DeriveKey    DeriveKeyFunc
	StopChan     <-chan struct{}
}

// VerifySolutionOptions configures solution verification.
type VerifySolutionOptions struct {
	Challenge              Challenge
	Solution               Solution
	DeriveKey              DeriveKeyFunc
	HMACAlgorithm          Algorithm
	HMACKeySignatureSecret string
	HMACSignatureSecret    string
}

// VerifySolutionResult holds the verification outcome.
type VerifySolutionResult struct {
	Expired          bool
	InvalidSignature *bool
	InvalidSolution  *bool
	Time             int64
	Verified         bool
}

// passwordWithCounter returns nonce with the counter appended as a big-endian uint32.
func passwordWithCounter(nonce []byte, n int) []byte {
	buf := make([]byte, len(nonce)+4)
	copy(buf, nonce)
	binary.BigEndian.PutUint32(buf[len(nonce):], uint32(n))
	return buf
}

// randomBytes generates a random byte array of the specified length.
func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	return b, err
}

// hashBytes computes a hash of data using the specified algorithm.
func hashBytes(algorithm Algorithm, data []byte) ([]byte, error) {
	switch algorithm {
	case SHA1:
		h := sha1.New()
		h.Write(data)
		return h.Sum(nil), nil
	case SHA256:
		h := sha256.New()
		h.Write(data)
		return h.Sum(nil), nil
	case SHA512:
		h := sha512.New()
		h.Write(data)
		return h.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// hmacHash computes HMAC of data using the specified algorithm and key.
func hmacHash(algorithm Algorithm, data []byte, key string) ([]byte, error) {
	switch algorithm {
	case SHA1:
		h := hmac.New(sha1.New, []byte(key))
		h.Write(data)
		return h.Sum(nil), nil
	case SHA256:
		h := hmac.New(sha256.New, []byte(key))
		h.Write(data)
		return h.Sum(nil), nil
	case SHA512:
		h := hmac.New(sha512.New, []byte(key))
		h.Write(data)
		return h.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// hmacHex computes HMAC and returns the hex-encoded result.
func hmacHex(algorithm Algorithm, data []byte, key string) (string, error) {
	h, err := hmacHash(algorithm, data, key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h), nil
}

// constantTimeEqual performs constant-time string comparison.
func constantTimeEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

// bufferStartsWith checks if buf starts with prefix.
func bufferStartsWith(buf, prefix []byte) bool {
	if len(buf) < len(prefix) {
		return false
	}
	for i, b := range prefix {
		if buf[i] != b {
			return false
		}
	}
	return true
}

// canonicalJSON marshals v to JSON with all object keys sorted recursively.
func canonicalJSON(v interface{}) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var parsed interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return "", err
	}
	out, err := marshalSorted(parsed)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// marshalSorted recursively serializes a value to JSON with sorted object keys.
func marshalSorted(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf strings.Builder
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			vb, err := marshalSorted(val[k])
			if err != nil {
				return nil, err
			}
			buf.Write(vb)
		}
		buf.WriteByte('}')
		return []byte(buf.String()), nil
	case []interface{}:
		var buf strings.Builder
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			vb, err := marshalSorted(item)
			if err != nil {
				return nil, err
			}
			buf.Write(vb)
		}
		buf.WriteByte(']')
		return []byte(buf.String()), nil
	default:
		return json.Marshal(v)
	}
}

// CreateChallenge creates a new v2 challenge.
func CreateChallenge(options CreateChallengeOptions) (Challenge, error) {
	algorithm := options.Algorithm
	if algorithm == "" {
		return Challenge{}, fmt.Errorf("Algorithm parameter is required")
	}

	cost := options.Cost
	if cost <= 0 {
		return Challenge{}, fmt.Errorf("Cost parameter must be greater than zero")
	}

	keyLength := options.KeyLength
	if keyLength <= 0 {
		keyLength = defaultKeyLength
	}

	keyPrefix := options.KeyPrefix
	keyPrefixLength := options.KeyPrefixLength
	if keyPrefixLength <= 0 {
		keyPrefixLength = keyLength / defaultKeyPrefixRatio
	}

	if options.Counter == nil {
		if keyPrefix == "" {
			keyPrefix = defaultKeyPrefix
		}
	}

	// Generate salt
	saltBytes, err := randomBytes(12)
	if err != nil {
		return Challenge{}, err
	}
	salt := hex.EncodeToString(saltBytes)

	// Generate nonce
	nonceBytes, err := randomBytes(12)
	if err != nil {
		return Challenge{}, err
	}
	nonce := hex.EncodeToString(nonceBytes)

	params := ChallengeParameters{
		Algorithm: algorithm,
		Nonce:     nonce,
		Salt:      salt,
		Cost:      cost,
		KeyLength: keyLength,
		KeyPrefix: keyPrefix,
		Data:      options.Data,
	}

	if options.MemoryCost > 0 {
		params.MemoryCost = options.MemoryCost
	}
	if options.Parallelism > 0 {
		params.Parallelism = options.Parallelism
	}
	if options.ExpiresAt != nil {
		params.ExpiresAt = options.ExpiresAt.Unix()
	}

	// If a deterministic counter is provided, derive the key and set the key prefix
	var derivedKey []byte
	if options.Counter != nil && options.DeriveKey != nil {
		saltBytes2, err := hex.DecodeString(salt)
		if err != nil {
			return Challenge{}, fmt.Errorf("invalid salt hex: %w", err)
		}
		nonceBytes2, err := hex.DecodeString(nonce)
		if err != nil {
			return Challenge{}, fmt.Errorf("invalid nonce hex: %w", err)
		}
		password := passwordWithCounter(nonceBytes2, *options.Counter)
		dk, err := options.DeriveKey(params, saltBytes2, password)
		if err != nil {
			return Challenge{}, err
		}
		derivedKey = dk
		params.KeyPrefix = hex.EncodeToString(derivedKey[:keyPrefixLength])
	}

	return signChallenge(options.HMACAlgorithm, params, derivedKey, options.HMACSignatureSecret, options.HMACKeySignatureSecret)
}

// signChallenge signs challenge parameters and returns a Challenge.
func signChallenge(hmacAlgorithm Algorithm, params ChallengeParameters, derivedKey []byte, hmacSecret string, hmacKeySecret string) (Challenge, error) {
	if hmacAlgorithm == "" {
		hmacAlgorithm = SHA256
	}

	challenge := Challenge{
		Parameters: params,
	}

	if len(derivedKey) > 0 && hmacKeySecret != "" {
		keySignature, err := hmacHex(hmacAlgorithm, derivedKey, hmacKeySecret)
		if err != nil {
			return Challenge{}, err
		}
		challenge.Parameters.KeySignature = keySignature
	}

	if hmacSecret != "" {
		paramsJSON, err := canonicalJSON(challenge.Parameters)
		if err != nil {
			return Challenge{}, err
		}
		signature, err := hmacHex(hmacAlgorithm, []byte(paramsJSON), hmacSecret)
		if err != nil {
			return Challenge{}, err
		}
		challenge.Signature = signature
	}

	return challenge, nil
}


// SolveChallenge attempts to solve a v2 challenge by brute-forcing the counter.
func SolveChallenge(options SolveChallengeOptions) (*Solution, error) {
	if options.DeriveKey == nil {
		return nil, fmt.Errorf("DeriveKey function is required")
	}

	counterStep := options.CounterStep
	if counterStep <= 0 {
		counterStep = 1
	}

	params := options.Challenge.Parameters
	prefix, err := hex.DecodeString(params.KeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("invalid key prefix hex: %w", err)
	}

	saltBytes, err := hex.DecodeString(params.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt hex: %w", err)
	}
	nonceBytes, err := hex.DecodeString(params.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce hex: %w", err)
	}

	startTime := time.Now()

	for n := options.CounterStart; ; n += counterStep {
		// Check for cancellation
		if options.StopChan != nil {
			select {
			case <-options.StopChan:
				return nil, nil
			default:
			}
		}

		password := passwordWithCounter(nonceBytes, n)
		derivedKey, err := options.DeriveKey(params, saltBytes, password)
		if err != nil {
			return nil, err
		}

		if bufferStartsWith(derivedKey, prefix) {
			elapsed := time.Since(startTime).Milliseconds()
			return &Solution{
				Counter:    n,
				DerivedKey: hex.EncodeToString(derivedKey),
				Time:       float64(elapsed),
			}, nil
		}
	}
}

// VerifySolution verifies a v2 solution against the challenge.
func VerifySolution(options VerifySolutionOptions) (VerifySolutionResult, error) {
	startTime := time.Now()
	result := VerifySolutionResult{}

	params := options.Challenge.Parameters

	// Check expiration
	if params.ExpiresAt > 0 {
		if time.Now().Unix() > params.ExpiresAt {
			result.Expired = true
			result.Time = time.Since(startTime).Milliseconds()
			return result, nil
		}
	}

	hmacAlgorithm := options.HMACAlgorithm
	if hmacAlgorithm == "" {
		hmacAlgorithm = SHA256
	}

	// Verify challenge signature
	if options.HMACSignatureSecret != "" {
		invalidSig := true
		result.InvalidSignature = &invalidSig

		paramsJSON, err := canonicalJSON(params)
		if err != nil {
			result.Time = time.Since(startTime).Milliseconds()
			return result, err
		}
		expectedSig, err := hmacHex(hmacAlgorithm, []byte(paramsJSON), options.HMACSignatureSecret)
		if err != nil {
			result.Time = time.Since(startTime).Milliseconds()
			return result, err
		}

		if constantTimeEqual(expectedSig, options.Challenge.Signature) {
			*result.InvalidSignature = false
		} else {
			result.Time = time.Since(startTime).Milliseconds()
			return result, nil
		}
	}

	// Fast path: verify solution via key signature (no re-derivation needed)
	if params.KeySignature != "" && options.HMACKeySignatureSecret != "" {
		invalidSol := true
		result.InvalidSolution = &invalidSol

		derivedKeyBytes, err := hex.DecodeString(options.Solution.DerivedKey)
		if err != nil {
			result.Time = time.Since(startTime).Milliseconds()
			return result, fmt.Errorf("invalid derived key hex: %w", err)
		}
		expectedKeySig, err := hmacHex(hmacAlgorithm, derivedKeyBytes, options.HMACKeySignatureSecret)
		if err != nil {
			result.Time = time.Since(startTime).Milliseconds()
			return result, err
		}
		if constantTimeEqual(params.KeySignature, expectedKeySig) {
			*result.InvalidSolution = false
			result.Verified = true
		}
		result.Time = time.Since(startTime).Milliseconds()
		return result, nil
	}

	// Slow path: re-derive and compare
	if options.DeriveKey != nil {
		invalidSol := true
		result.InvalidSolution = &invalidSol

		saltBytes, err := hex.DecodeString(params.Salt)
		if err != nil {
			result.Time = time.Since(startTime).Milliseconds()
			return result, fmt.Errorf("invalid salt hex: %w", err)
		}
		nonceBytes, err := hex.DecodeString(params.Nonce)
		if err != nil {
			result.Time = time.Since(startTime).Milliseconds()
			return result, fmt.Errorf("invalid nonce hex: %w", err)
		}
		password := passwordWithCounter(nonceBytes, options.Solution.Counter)
		derivedKey, err := options.DeriveKey(params, saltBytes, password)
		if err != nil {
			result.Time = time.Since(startTime).Milliseconds()
			return result, err
		}

		expectedDerivedKey := hex.EncodeToString(derivedKey)

		prefix, err := hex.DecodeString(params.KeyPrefix)
		if err != nil {
			result.Time = time.Since(startTime).Milliseconds()
			return result, fmt.Errorf("invalid key prefix hex: %w", err)
		}

		if constantTimeEqual(expectedDerivedKey, options.Solution.DerivedKey) && bufferStartsWith(derivedKey, prefix) {
			*result.InvalidSolution = false
			result.Verified = true
		}
	} else {
		// No DeriveKey and no key signature — verify by signature only
		if result.InvalidSignature != nil && !*result.InvalidSignature {
			result.Verified = true
		}
	}

	result.Time = time.Since(startTime).Milliseconds()
	return result, nil
}
