package altcha

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ServerSignaturePayload represents the structure of the payload for server signature verification.
type ServerSignaturePayload struct {
	Algorithm        Algorithm `json:"algorithm"`
	VerificationData string    `json:"verificationData"`
	Signature        string    `json:"signature"`
	Verified         bool      `json:"verified"`
}

// ServerSignatureVerificationData represents the extracted verification data.
type ServerSignatureVerificationData struct {
	Classification   string   `json:"classification,omitempty"`
	Country          string   `json:"country,omitempty"`
	DetectedLanguage string   `json:"detectedLanguage,omitempty"`
	Email            string   `json:"email,omitempty"`
	Expire           int64    `json:"expire,omitempty"`
	Fields           []string `json:"fields,omitempty"`
	FieldsHash       string   `json:"fieldsHash,omitempty"`
	IpAddress        string   `json:"ipAddress,omitempty"`
	Reasons          []string `json:"reasons,omitempty"`
	Score            float64  `json:"score,omitempty"`
	Time             int64    `json:"time,omitempty"`
	Verified         bool     `json:"verified,omitempty"`

	Extra map[string]string `json:"-"`
}

// VerifyServerSignatureResult holds the outcome of server signature verification.
type VerifyServerSignatureResult struct {
	Expired          bool
	InvalidSignature bool
	InvalidSolution  bool
	Time             int64
	VerificationData *ServerSignatureVerificationData
	Verified         bool
}

var knownFields = map[string]bool{
	"classification":   true,
	"country":          true,
	"detectedLanguage": true,
	"email":            true,
	"expire":           true,
	"fields":           true,
	"fieldsHash":       true,
	"ipAddress":        true,
	"reasons":          true,
	"score":            true,
	"time":             true,
	"verified":         true,
}

// ParseVerificationData parses a URL-encoded verification data string.
// Returns nil if the data cannot be parsed.
func ParseVerificationData(data string) *ServerSignatureVerificationData {
	params, err := url.ParseQuery(data)
	if err != nil {
		return nil
	}

	vd := &ServerSignatureVerificationData{
		Extra: make(map[string]string),
	}

	vd.Classification = params.Get("classification")
	vd.Country = params.Get("country")
	vd.DetectedLanguage = params.Get("detectedLanguage")
	vd.Email = params.Get("email")
	vd.Expire, _ = strconv.ParseInt(params.Get("expire"), 10, 64)
	vd.FieldsHash = params.Get("fieldsHash")
	vd.IpAddress = params.Get("ipAddress")
	vd.Score, _ = strconv.ParseFloat(params.Get("score"), 64)
	vd.Time, _ = strconv.ParseInt(params.Get("time"), 10, 64)
	vd.Verified = params.Get("verified") == "true"

	if f := params.Get("fields"); f != "" {
		vd.Fields = strings.Split(f, ",")
	}
	if r := params.Get("reasons"); r != "" {
		vd.Reasons = strings.Split(r, ",")
	}

	for key, values := range params {
		if !knownFields[key] && len(values) > 0 {
			vd.Extra[key] = values[0]
		}
	}

	return vd
}

// parsePayload decodes a ServerSignaturePayload from either a base64 JSON string or a struct value.
func parsePayload(payload interface{}) (ServerSignaturePayload, error) {
	switch v := payload.(type) {
	case string:
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return ServerSignaturePayload{}, err
		}
		var p ServerSignaturePayload
		if err := json.Unmarshal(decoded, &p); err != nil {
			return ServerSignaturePayload{}, err
		}
		return p, nil
	default:
		p, _ := v.(ServerSignaturePayload)
		return p, nil
	}
}

// getExpectedServerSignature computes the expected HMAC signature for a server signature payload.
func getExpectedServerSignature(payload ServerSignaturePayload, hmacKey string) (string, error) {
	h, err := hashBytes(payload.Algorithm, []byte(payload.VerificationData))
	if err != nil {
		return "", err
	}
	return hmacHex(payload.Algorithm, h, hmacKey)
}

// VerifyServerSignature verifies the server's signature and returns a detailed result.
// payload may be a ServerSignaturePayload struct or a base64-encoded JSON string.
func VerifyServerSignature(payload interface{}, hmacKey string) (VerifyServerSignatureResult, error) {
	startTime := time.Now()

	parsedPayload, err := parsePayload(payload)
	if err != nil {
		return VerifyServerSignatureResult{}, err
	}

	expectedSignature, err := getExpectedServerSignature(parsedPayload, hmacKey)
	if err != nil {
		return VerifyServerSignatureResult{}, err
	}

	vd := ParseVerificationData(parsedPayload.VerificationData)

	expired := vd != nil && vd.Expire > 0 && vd.Expire < time.Now().Unix()
	invalidSignature := !constantTimeEqual(parsedPayload.Signature, expectedSignature)
	invalidSolution := vd == nil || !vd.Verified || !parsedPayload.Verified
	verified := !expired && !invalidSignature && !invalidSolution

	return VerifyServerSignatureResult{
		Expired:          expired,
		InvalidSignature: invalidSignature,
		InvalidSolution:  invalidSolution,
		Time:             time.Since(startTime).Milliseconds(),
		VerificationData: vd,
		Verified:         verified,
	}, nil
}

// VerifyFieldsHash verifies the hash of form fields against an expected hash.
func VerifyFieldsHash(formData map[string][]string, fields []string, fieldsHash string, algorithm Algorithm) (bool, error) {
	lines := make([]string, len(fields))
	for i, field := range fields {
		if values, ok := formData[field]; ok && len(values) > 0 {
			lines[i] = values[0]
		}
	}
	h, err := hashBytes(algorithm, []byte(strings.Join(lines, "\n")))
	if err != nil {
		return false, err
	}
	return constantTimeEqual(hex.EncodeToString(h), fieldsHash), nil
}
