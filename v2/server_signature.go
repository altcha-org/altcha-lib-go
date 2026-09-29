package altcha

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
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

// ServerSignatureVerificationData is the verification data signed by ALTCHA Sentinel.
//
// Sentinel groups related values under dotted keys (location.countryCode=US).
// Those map onto the nested structs below; a group is nil when Sentinel did not
// report it. The same struct decodes the nested JSON returned by
// /v1/verify/signature ({"location":{"countryCode":"US"}}).
type ServerSignatureVerificationData struct {
	ChallengeAlgorithm string                `json:"challengeAlgorithm,omitempty"`
	Classification     string                `json:"classification,omitempty"`
	Device             *VerificationDevice   `json:"device,omitempty"`
	Email              *VerificationScore    `json:"email,omitempty"`
	Expire             int64                 `json:"expire,omitempty"`
	Fields             []string              `json:"fields,omitempty"`
	FieldsHash         string                `json:"fieldsHash,omitempty"`
	Id                 string                `json:"id,omitempty"`
	IP                 *VerificationScore    `json:"ip,omitempty"`
	IpAddress          string                `json:"ipAddress,omitempty"`
	Location           *VerificationLocation `json:"location,omitempty"`
	Origin             string                `json:"origin,omitempty"`
	// Params holds the challenge's params.* values, keyed without the "params." prefix.
	Params   map[string]string `json:"params,omitempty"`
	Penalty  float64           `json:"penalty,omitempty"`
	Reasons  []string          `json:"reasons,omitempty"`
	Score    float64           `json:"score,omitempty"`
	Text     *VerificationText `json:"text,omitempty"`
	Time     int64             `json:"time,omitempty"`
	Verified bool              `json:"verified,omitempty"`

	// Extra holds any other values, keyed by their dotted name (e.g. "hisScore").
	Extra map[string]string `json:"-"`
}

// VerificationDevice describes the client device (device.* keys).
type VerificationDevice struct {
	Browser string `json:"browser,omitempty"`
	Edk     string `json:"edk,omitempty"`
	Type    string `json:"type,omitempty"`
}

// VerificationLocation is the location classification (location.* keys).
type VerificationLocation struct {
	CountryCode    string  `json:"countryCode,omitempty"`
	Score          float64 `json:"score,omitempty"`
	TimeZone       string  `json:"timeZone,omitempty"`
	TriggeredRules string  `json:"triggeredRules,omitempty"`
}

// VerificationText is the text classification (text.* keys).
type VerificationText struct {
	Language       string  `json:"language,omitempty"`
	Score          float64 `json:"score,omitempty"`
	TriggeredRules string  `json:"triggeredRules,omitempty"`
}

// VerificationScore is the email or IP classification (email.* and ip.* keys).
type VerificationScore struct {
	Score          float64 `json:"score,omitempty"`
	TriggeredRules string  `json:"triggeredRules,omitempty"`
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

// ParseVerificationData parses a URL-encoded verification data string.
// Returns nil if the data cannot be parsed.
func ParseVerificationData(data string) *ServerSignatureVerificationData {
	params, err := url.ParseQuery(data)
	if err != nil {
		return nil
	}
	vd := &ServerSignatureVerificationData{Extra: make(map[string]string)}
	for key, values := range params {
		vd.set(key, values[len(values)-1])
	}
	return vd
}

// UnmarshalJSON decodes the nested verification data returned by Sentinel's
// /v1/verify/signature API. Decoding is lenient: values of an unexpected type
// are coerced where possible (an all-digit id sent as a JSON number stays the
// id) and otherwise ignored, so they never fail the enclosing decode.
func (vd *ServerSignatureVerificationData) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var raw interface{}
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	*vd = ServerSignatureVerificationData{Extra: make(map[string]string)}
	if obj, ok := raw.(map[string]interface{}); ok {
		vd.setJSON("", obj)
	}
	return nil
}

// setJSON flattens a decoded JSON object into dotted keys and assigns them.
func (vd *ServerSignatureVerificationData) setJSON(prefix string, obj map[string]interface{}) {
	for k, v := range obj {
		if nested, ok := v.(map[string]interface{}); ok {
			vd.setJSON(prefix+k+".", nested)
		} else if s, ok := jsonText(v); ok {
			vd.set(prefix+k, s)
		}
	}
}

// jsonText renders a decoded JSON scalar, or an array of scalars joined with
// commas, the way it appears in URL-encoded verification data.
func jsonText(v interface{}) (string, bool) {
	switch val := v.(type) {
	case string:
		return val, true
	case json.Number:
		return val.String(), true
	case bool:
		return strconv.FormatBool(val), true
	case []interface{}:
		items := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := jsonText(item); ok {
				items = append(items, s)
			}
		}
		return strings.Join(items, ","), true
	}
	return "", false
}

// set assigns one verification data value by its dotted key.
func (vd *ServerSignatureVerificationData) set(key, value string) {
	value = strings.TrimSpace(value)
	switch key {
	case "challengeAlgorithm":
		vd.ChallengeAlgorithm = value
	case "classification":
		vd.Classification = value
	case "expire":
		vd.Expire = parseInt64(value)
	case "fields":
		vd.Fields = splitList(value)
	case "fieldsHash":
		vd.FieldsHash = value
	case "id":
		vd.Id = value
	case "ipAddress":
		vd.IpAddress = value
	case "origin":
		vd.Origin = value
	case "penalty":
		vd.Penalty = parseFloat64(value)
	case "reasons":
		vd.Reasons = splitList(value)
	case "score":
		vd.Score = parseFloat64(value)
	case "time":
		vd.Time = parseInt64(value)
	case "verified":
		vd.Verified = value == "true"
	case "device.browser":
		group(&vd.Device).Browser = value
	case "device.edk":
		group(&vd.Device).Edk = value
	case "device.type":
		group(&vd.Device).Type = value
	case "email.score":
		group(&vd.Email).Score = parseFloat64(value)
	case "email.triggeredRules":
		group(&vd.Email).TriggeredRules = value
	case "ip.score":
		group(&vd.IP).Score = parseFloat64(value)
	case "ip.triggeredRules":
		group(&vd.IP).TriggeredRules = value
	case "location.countryCode":
		group(&vd.Location).CountryCode = value
	case "location.score":
		group(&vd.Location).Score = parseFloat64(value)
	case "location.timeZone":
		group(&vd.Location).TimeZone = value
	case "location.triggeredRules":
		group(&vd.Location).TriggeredRules = value
	case "text.language":
		group(&vd.Text).Language = value
	case "text.score":
		group(&vd.Text).Score = parseFloat64(value)
	case "text.triggeredRules":
		group(&vd.Text).TriggeredRules = value
	default:
		if name, ok := strings.CutPrefix(key, "params."); ok && name != "" {
			if vd.Params == nil {
				vd.Params = make(map[string]string)
			}
			vd.Params[name] = value
			return
		}
		if vd.Extra == nil {
			vd.Extra = make(map[string]string)
		}
		vd.Extra[key] = value
	}
}

// group returns *p, allocating it first if nil.
func group[T any](p **T) *T {
	if *p == nil {
		*p = new(T)
	}
	return *p
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func parseFloat64(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) {
		return 0
	}
	return f
}

func parseInt64(s string) int64 {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	return int64(parseFloat64(s))
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
