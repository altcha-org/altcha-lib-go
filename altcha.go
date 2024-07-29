package altcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
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
	DefaultMaxNumber  int64 = 1e6
	DefaultSaltLength int   = 12
	DefaultAlgorithm        = SHA256
)

// ChallengeOptions defines the options for creating a challenge
type ChallengeOptions struct {
	Algorithm  Algorithm
	MaxNumber  int64
	SaltLength int
	HMACKey    string
	Salt       string
	Number     int64
	Expires    *time.Time
	Params     url.Values
}

// Challenge represents a challenge for the client to solve
type Challenge struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	MaxNumber int64  `json:"maxNumber"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

// Payload represents a solution to a Challenge
type Payload struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int64  `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

// ServerSignaturePayload represents the structure of the payload for server signature verification
type ServerSignaturePayload struct {
	Algorithm        Algorithm `json:"algorithm"`
	VerificationData string    `json:"verificationData"`
	Signature        string    `json:"signature"`
	Verified         bool      `json:"verified"`
}

// ServerSignatureVerificationData represents the extracted verification data
type ServerSignatureVerificationData struct {
	Classification   string   `json:"classification"`
	Country          string   `json:"country"`
	DetectedLanguage string   `json:"detectedLanguage"`
	Email            string   `json:"email"`
	Expire           int64    `json:"expire"`
	Fields           []string `json:"fields"`
	FieldsHash       string   `json:"fieldsHash"`
	IpAddress        string   `json:"ipAddress"`
	Reasons          []string `json:"reasons"`
	Score            float64  `json:"score"`
	Time             int64    `json:"time"`
	Verified         bool     `json:"verified"`
}

// Solution holds the result of solving a challenge.
type Solution struct {
	Number int
	Took   time.Duration
}

// Generates a random byte array of the specified length
func randomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	return bytes, err
}

// Generates a random integer between 0 and max (inclusive)
func randomInt(max int64) (int64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(max+1))
	if err != nil {
		return 0, err
	}
	return n.Int64(), nil
}

// Hashes the input data using the specified algorithm and returns the hexadecimal representation of the hash
func hashHex(algorithm Algorithm, data string) (string, error) {
	hash, err := hash(algorithm, []byte(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash), nil
}

// Hashes the input data using the specified algorithm
func hash(algorithm Algorithm, data []byte) ([]byte, error) {
	var hash []byte
	switch algorithm {
	case SHA1:
		h := sha1.New()
		h.Write([]byte(data))
		hash = h.Sum(nil)
	case SHA256:
		h := sha256.New()
		h.Write([]byte(data))
		hash = h.Sum(nil)
	case SHA512:
		h := sha512.New()
		h.Write([]byte(data))
		hash = h.Sum(nil)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	return hash, nil
}

// Computes the HMAC of the input data using the specified algorithm and key, and returns the hexadecimal representation
func hmacHex(algorithm Algorithm, data []byte, key string) (string, error) {
	h, err := hmacHash(algorithm, []byte(data), key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h), nil
}

// Computes the HMAC of the input data using the specified algorithm and key
func hmacHash(algorithm Algorithm, data []byte, key string) ([]byte, error) {
	var hash []byte
	switch algorithm {
	case SHA1:
		h := hmac.New(sha1.New, []byte(key))
		h.Write(data)
		hash = h.Sum(nil)
	case SHA256:
		h := hmac.New(sha256.New, []byte(key))
		h.Write(data)
		hash = h.Sum(nil)
	case SHA512:
		h := hmac.New(sha512.New, []byte(key))
		h.Write(data)
		hash = h.Sum(nil)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	return hash, nil
}

// Creates a challenge for the client to solve
func CreateChallenge(options ChallengeOptions) (Challenge, error) {
	algorithm := options.Algorithm
	if algorithm == "" {
		algorithm = DefaultAlgorithm
	}
	maxNumber := options.MaxNumber
	if maxNumber == 0 {
		maxNumber = DefaultMaxNumber
	}
	saltLength := options.SaltLength
	if saltLength == 0 {
		saltLength = DefaultSaltLength
	}
	
	if options.Params == nil {
		options.Params = url.Values{}
	}

	params := options.Params
	if options.Expires != nil {
		params.Set("expires", fmt.Sprintf("%d", options.Expires.Unix()))
	}
	salt := options.Salt
	if salt == "" {
		randomSalt, err := randomBytes(saltLength)
		if err != nil {
			return Challenge{}, err
		}
		salt = hex.EncodeToString(randomSalt)
	}
	if len(params) > 0 {
		salt = salt + "?" + params.Encode()
	}

	number := options.Number
	if number == 0 {
		randomNumber, err := randomInt(maxNumber)
		if err != nil {
			return Challenge{}, err
		}
		number = randomNumber
	}

	challenge, err := hashHex(algorithm, salt+fmt.Sprint(number))
	if err != nil {
		return Challenge{}, err
	}

	signature, err := hmacHex(algorithm, []byte(challenge), options.HMACKey)
	if err != nil {
		return Challenge{}, err
	}

	return Challenge{
		Algorithm: string(algorithm),
		Challenge: challenge,
		MaxNumber: maxNumber,
		Salt:      salt,
		Signature: signature,
	}, nil
}

// Verifies the solution provided by the client
func VerifySolution(payload interface{}, hmacKey string, checkExpires bool) (bool, error) {
	var parsedPayload Payload

	// Parse payload
	switch v := payload.(type) {
	case string:
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return false, err
		}
		err = json.Unmarshal(decoded, &parsedPayload)
		if err != nil {
			return false, err
		}
	default:
		parsedPayload, _ = v.(Payload)
	}

	params := ExtractParams(parsedPayload)
	expires := params.Get("expires")
	if checkExpires && expires != "" {
		expireTime, err := strconv.ParseInt(expires, 10, 64)
		if err != nil {
			return false, err
		}
		if time.Now().Unix() > expireTime {
			return false, nil
		}
	}

	challengeOptions := ChallengeOptions{
		Algorithm: Algorithm(parsedPayload.Algorithm),
		HMACKey:   hmacKey,
		Number:    parsedPayload.Number,
		Salt:      parsedPayload.Salt,
	}
	expectedChallenge, err := CreateChallenge(challengeOptions)
	if err != nil {
		return false, err
	}

	return expectedChallenge.Challenge == parsedPayload.Challenge && expectedChallenge.Signature == parsedPayload.Signature, nil
}

// Extracts parameters from the payload
func ExtractParams(payload Payload) url.Values {
	splitSalt := strings.Split(payload.Salt, "?")
	if len(splitSalt) > 1 {
		params, _ := url.ParseQuery(splitSalt[1])
		return params
	}
	return url.Values{}
}

// Verifies the hash of form fields
func VerifyFieldsHash(formData map[string][]string, fields []string, fieldsHash string, algorithm Algorithm) (bool, error) {
	var lines []string
	for _, field := range fields {
		if value, exists := formData[field]; exists && len(value) > 0 {
			lines = append(lines, value[0])
		} else {
			lines = append(lines, "")
		}
	}

	joinedData := strings.Join(lines, "\n")
	computedHash, err := hashHex(algorithm, joinedData)
	if err != nil {
		return false, err
	}

	return computedHash == fieldsHash, nil
}

// VerifyServerSignature verifies the server's signature
func VerifyServerSignature(payload interface{}, hmacKey string) (bool, ServerSignatureVerificationData, error) {
	var parsedPayload ServerSignaturePayload

	// Parse payload
	switch v := payload.(type) {
	case string:
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return false, ServerSignatureVerificationData{}, err
		}
		err = json.Unmarshal(decoded, &parsedPayload)
		if err != nil {
			return false, ServerSignatureVerificationData{}, err
		}
	default:
		parsedPayload, _ = v.(ServerSignaturePayload)
	}

	// Calculate expected signature
	hash, err := hash(parsedPayload.Algorithm, []byte(parsedPayload.VerificationData))
	if err != nil {
		return false, ServerSignatureVerificationData{}, err
	}
	expectedSignature, err := hmacHex(parsedPayload.Algorithm, hash, hmacKey)
	if err != nil {
		return false, ServerSignatureVerificationData{}, err
	}

	// Extract verification data
	var verificationData ServerSignatureVerificationData
	params, err := url.ParseQuery(parsedPayload.VerificationData)
	if err == nil {
		verificationData.Classification = params.Get("classification")
		verificationData.Country = params.Get("country")
		verificationData.DetectedLanguage = params.Get("detectedLanguage")
		verificationData.Email = params.Get("email")
		verificationData.Expire, _ = strconv.ParseInt(params.Get("expire"), 10, 64)
		verificationData.Fields = strings.Split(params.Get("fields"), ",")
		verificationData.Reasons = strings.Split(params.Get("reasons"), ",")
		verificationData.Score, _ = strconv.ParseFloat(params.Get("score"), 64)
		verificationData.Time, _ = strconv.ParseInt(params.Get("time"), 10, 64)
		verificationData.Verified = params.Get("verified") == "true"
	}

	// Verify the signature
	now := time.Now().Unix()
	isVerified := parsedPayload.Verified &&
		verificationData.Verified &&
		verificationData.Expire > now &&
		parsedPayload.Signature == expectedSignature

	return isVerified, verificationData, nil
}

// SolveChallenge solves a challenge
func SolveChallenge(challenge string, salt string, algorithm Algorithm, max int, start int, stopChan <-chan struct{}) (*Solution, error) {
	if algorithm == "" {
		algorithm = "SHA-256"
	}
	if max <= 0 {
		max = 1000000
	}
	if start < 0 {
		start = 0
	}

	startTime := time.Now()

	for n := start; n <= max; n++ {
		select {
		case <-stopChan:
			// Stop the process if the stop signal is received.
			return nil, nil
		default:
			// Continue the process.
		}

		hash, err := hashHex(algorithm, salt+fmt.Sprint(n))
		if err != nil {
			return nil, err
		}
		if hash == challenge {
			return &Solution{
				Number: n,
				Took:   time.Since(startTime),
			}, nil
		}
	}

	return nil, nil
}
