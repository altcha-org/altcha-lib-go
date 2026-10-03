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
	"strconv"
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
	saltLength            = 16 // bytes
	nonceLength           = 16 // bytes
	defaultSolveTimeout   = 90 * time.Second
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

	// rawData is the "data" value exactly as decoded by UnmarshalJSON. A Go map
	// cannot hold key order, so it is re-emitted verbatim while Data still
	// matches it; see MarshalJSON.
	rawData json.RawMessage

	// rawMemoryCost, rawParallelism and rawExpiresAt hold those keys exactly
	// as decoded by UnmarshalJSON when they decoded to zero (0 or null).
	// omitempty would drop them, but altcha-lib signs every key it sends, so
	// they are re-emitted while the field is still zero; see MarshalJSON.
	rawMemoryCost  json.RawMessage
	rawParallelism json.RawMessage
	rawExpiresAt   json.RawMessage
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

// CounterMode selects how the counter is appended to the nonce to form the
// key derivation password.
type CounterMode string

const (
	// CounterModeUint32 appends the counter as a big-endian uint32 (v2 default).
	CounterModeUint32 CounterMode = "uint32"
	// CounterModeString appends the counter as a decimal string, for
	// backward compatibility with v1.
	CounterModeString CounterMode = "string"
)

// validate rejects unknown modes; the zero value means CounterModeUint32.
func (m CounterMode) validate() error {
	switch m {
	case "", CounterModeUint32, CounterModeString:
		return nil
	}
	return fmt.Errorf("unsupported CounterMode %q", string(m))
}

// CreateChallengeOptions configures challenge creation.
type CreateChallengeOptions struct {
	Algorithm              string
	Cost                   int
	Counter                *int
	CounterMode            CounterMode // default: CounterModeUint32
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
	CounterMode  CounterMode // default: CounterModeUint32
	CounterStart int
	CounterStep  int
	DeriveKey    DeriveKeyFunc
	StopChan     <-chan struct{}
	// Timeout bounds the solving time (default: 90s, as in altcha-lib).
	// A negative value disables it.
	Timeout time.Duration
}

// VerifySolutionOptions configures solution verification.
type VerifySolutionOptions struct {
	Challenge              Challenge
	Solution               Solution
	CounterMode            CounterMode // default: CounterModeUint32
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

// passwordWithCounter returns nonce with the counter appended as mode
// specifies (a valid mode; see CounterMode.validate).
func passwordWithCounter(nonce []byte, n int, mode CounterMode) []byte {
	if mode == CounterModeString {
		// Room for the longest int64, "-9223372036854775808".
		buf := make([]byte, len(nonce), len(nonce)+20)
		copy(buf, nonce)
		return strconv.AppendInt(buf, int64(n), 10)
	}
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

// keyPrefix is a parsed hex key prefix. Odd-length prefixes are supported:
// the trailing hex digit is matched against the high nibble of the next byte.
// Matching ignores hex case.
type keyPrefix struct {
	bytes     []byte
	nibble    byte // high nibble of the byte following bytes, low nibble zero
	hasNibble bool
}

// parseKeyPrefix decodes a hex key prefix of any length, in either case.
func parseKeyPrefix(s string) (keyPrefix, error) {
	even := len(s) &^ 1
	b, err := hex.DecodeString(s[:even])
	if err != nil {
		return keyPrefix{}, fmt.Errorf("invalid key prefix hex: %w", err)
	}
	p := keyPrefix{bytes: b}
	if even != len(s) {
		n, err := hex.DecodeString(s[even:] + "0")
		if err != nil {
			return keyPrefix{}, fmt.Errorf("invalid key prefix hex: %w", err)
		}
		p.nibble = n[0]
		p.hasNibble = true
	}
	return p, nil
}

// matches reports whether key starts with the prefix.
func (p keyPrefix) matches(key []byte) bool {
	if !bufferStartsWith(key, p.bytes) {
		return false
	}
	if !p.hasNibble {
		return true
	}
	return len(key) > len(p.bytes) && key[len(p.bytes)]&0xf0 == p.nibble
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

	if options.Counter != nil && options.DeriveKey == nil {
		return Challenge{}, fmt.Errorf("DeriveKey function is required when Counter is set")
	}
	if err := options.CounterMode.validate(); err != nil {
		return Challenge{}, err
	}

	keyLength := options.KeyLength
	if keyLength <= 0 {
		keyLength = defaultKeyLength
	}

	// Lowercase before signing so every client, including ones that compare
	// odd-length prefixes as strings against the lowercase hex key, can match it.
	keyPrefix := strings.ToLower(options.KeyPrefix)
	if keyPrefix == "" {
		keyPrefix = defaultKeyPrefix
	}
	// With a counter the prefix is derived from the key instead.
	if options.Counter == nil {
		if _, err := parseKeyPrefix(keyPrefix); err != nil {
			return Challenge{}, err
		}
	}
	keyPrefixLength := options.KeyPrefixLength
	if keyPrefixLength <= 0 {
		keyPrefixLength = keyLength / defaultKeyPrefixRatio
	}

	// Generate salt
	saltBytes, err := randomBytes(saltLength)
	if err != nil {
		return Challenge{}, err
	}
	salt := hex.EncodeToString(saltBytes)

	// Generate nonce
	nonceBytes, err := randomBytes(nonceLength)
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
	if options.Counter != nil {
		saltBytes2, err := hex.DecodeString(salt)
		if err != nil {
			return Challenge{}, fmt.Errorf("invalid salt hex: %w", err)
		}
		nonceBytes2, err := hex.DecodeString(nonce)
		if err != nil {
			return Challenge{}, fmt.Errorf("invalid nonce hex: %w", err)
		}
		password := passwordWithCounter(nonceBytes2, *options.Counter, options.CounterMode)
		dk, err := options.DeriveKey(params, saltBytes2, password)
		if err != nil {
			return Challenge{}, err
		}
		derivedKey = dk
		// Clamp like JS slice(): a prefix longer than the key is the whole key.
		params.KeyPrefix = hex.EncodeToString(derivedKey[:min(keyPrefixLength, len(derivedKey))])
	}

	return signChallenge(options.HMACAlgorithm, params, derivedKey, options.HMACSignatureSecret, options.HMACKeySignatureSecret)
}

// signChallenge signs challenge parameters and returns a Challenge. Without
// hmacSecret the challenge is returned unsigned, without a keySignature either
// (as in altcha-lib): VerifySolution would reject it for the missing signature.
func signChallenge(hmacAlgorithm Algorithm, params ChallengeParameters, derivedKey []byte, hmacSecret string, hmacKeySecret string) (Challenge, error) {
	if hmacSecret == "" {
		return Challenge{Parameters: params}, nil
	}
	if hmacAlgorithm == "" {
		hmacAlgorithm = SHA256
	}

	if len(derivedKey) > 0 && hmacKeySecret != "" {
		keySignature, err := hmacHex(hmacAlgorithm, derivedKey, hmacKeySecret)
		if err != nil {
			return Challenge{}, err
		}
		params.KeySignature = keySignature
	}

	paramsJSON, err := canonicalJSON(params)
	if err != nil {
		return Challenge{}, err
	}
	signature, err := hmacHex(hmacAlgorithm, []byte(paramsJSON), hmacSecret)
	if err != nil {
		return Challenge{}, err
	}
	return Challenge{Parameters: params, Signature: signature}, nil
}

// SolveChallenge attempts to solve a v2 challenge by brute-forcing the counter.
func SolveChallenge(options SolveChallengeOptions) (*Solution, error) {
	if options.DeriveKey == nil {
		return nil, fmt.Errorf("DeriveKey function is required")
	}
	if err := options.CounterMode.validate(); err != nil {
		return nil, err
	}

	counterStep := options.CounterStep
	if counterStep <= 0 {
		counterStep = 1
	}

	params := options.Challenge.Parameters
	prefix, err := parseKeyPrefix(params.KeyPrefix)
	if err != nil {
		return nil, err
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

	timeout := options.Timeout
	if timeout == 0 {
		timeout = defaultSolveTimeout
	}

	for n := options.CounterStart; ; n += counterStep {
		// Check for cancellation and timeout
		if options.StopChan != nil {
			select {
			case <-options.StopChan:
				return nil, nil
			default:
			}
		}
		if timeout > 0 && time.Since(startTime) > timeout {
			return nil, nil
		}

		password := passwordWithCounter(nonceBytes, n, options.CounterMode)
		derivedKey, err := options.DeriveKey(params, saltBytes, password)
		if err != nil {
			return nil, err
		}

		if prefix.matches(derivedKey) {
			elapsed := time.Since(startTime).Milliseconds()
			return &Solution{
				Counter:    n,
				DerivedKey: hex.EncodeToString(derivedKey),
				Time:       float64(elapsed),
			}, nil
		}
	}
}

// isExpired reports whether expiresAt (unix seconds) is before now, compared
// with sub-second precision like JS `expiresAt && expiresAt < Date.now() / 1000`.
// Zero means no expiry; negative values are in the past.
func isExpired(expiresAt int64, now time.Time) bool {
	if expiresAt == 0 {
		return false
	}
	sec := now.Unix()
	return expiresAt < sec || (expiresAt == sec && now.Nanosecond() > 0)
}

// VerifySolution verifies a v2 solution against the challenge.
func VerifySolution(options VerifySolutionOptions) (VerifySolutionResult, error) {
	startTime := time.Now()
	result := VerifySolutionResult{}

	if options.HMACSignatureSecret == "" {
		result.Time = time.Since(startTime).Milliseconds()
		return result, fmt.Errorf("HMACSignatureSecret is required")
	}
	if err := options.CounterMode.validate(); err != nil {
		result.Time = time.Since(startTime).Milliseconds()
		return result, err
	}

	params := options.Challenge.Parameters

	// Check expiration
	if isExpired(params.ExpiresAt, startTime) {
		result.Expired = true
		result.Time = time.Since(startTime).Milliseconds()
		return result, nil
	}

	hmacAlgorithm := options.HMACAlgorithm
	if hmacAlgorithm == "" {
		hmacAlgorithm = SHA256
	}

	// Verify challenge signature
	invalidSig := true
	result.InvalidSignature = &invalidSig

	if options.Challenge.Signature == "" {
		result.Time = time.Since(startTime).Milliseconds()
		return result, nil
	}

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

	if !constantTimeEqual(expectedSig, options.Challenge.Signature) {
		result.Time = time.Since(startTime).Milliseconds()
		return result, nil
	}
	*result.InvalidSignature = false

	// Fast path: verify solution via key signature (no re-derivation needed)
	if params.KeySignature != "" && options.HMACKeySignatureSecret != "" {
		invalidSol := true
		result.InvalidSolution = &invalidSol

		// Malformed hex is attacker input, not a server error: it can never
		// match, so report an invalid solution.
		derivedKeyBytes, err := hex.DecodeString(options.Solution.DerivedKey)
		if err != nil {
			result.Time = time.Since(startTime).Milliseconds()
			return result, nil
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
	if options.DeriveKey == nil {
		result.Time = time.Since(startTime).Milliseconds()
		return result, fmt.Errorf("DeriveKey function is required")
	}

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
	password := passwordWithCounter(nonceBytes, options.Solution.Counter, options.CounterMode)
	derivedKey, err := options.DeriveKey(params, saltBytes, password)
	if err != nil {
		result.Time = time.Since(startTime).Milliseconds()
		return result, err
	}

	expectedDerivedKey := hex.EncodeToString(derivedKey)

	prefix, err := parseKeyPrefix(params.KeyPrefix)
	if err != nil {
		result.Time = time.Since(startTime).Milliseconds()
		return result, err
	}

	if constantTimeEqual(expectedDerivedKey, options.Solution.DerivedKey) && prefix.matches(derivedKey) {
		*result.InvalidSolution = false
		result.Verified = true
	}

	result.Time = time.Since(startTime).Milliseconds()
	return result, nil
}
