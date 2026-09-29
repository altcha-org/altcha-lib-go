package altcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// canonicalJSON serializes v byte for byte like altcha-lib's
// canonicalJSON, i.e. JSON.stringify(sortKeys(v)):
//   - object keys are sorted recursively, but nothing below an array is
//     reordered (sortKeys stops at arrays);
//   - keys are compared by UTF-16 code units, and integer-like keys ("2",
//     "10") come first in numeric order, as in any JS object;
//   - strings are escaped as JSON.stringify does (no HTML or U+2028/U+2029
//     escaping), and numbers are formatted as JS numbers.
func canonicalJSON(v interface{}) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	parsed, err := parseOrderedJSON(b)
	if err != nil {
		return "", err
	}
	return string(appendCanonical(nil, parsed, true)), nil
}

type orderedMember struct {
	key   string
	value interface{}
}

// orderedObject is a JSON object with its keys in source order.
type orderedObject []orderedMember

// parseOrderedJSON decodes b into nil, bool, string, json.Number,
// []interface{} and orderedObject values, keeping object key order.
func parseOrderedJSON(b []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := readOrderedJSON(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("altcha: unexpected data after JSON value")
	}
	return v, nil
}

func readOrderedJSON(dec *json.Decoder) (interface{}, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch delim {
	case '{':
		obj := orderedObject{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, _ := keyTok.(string)
			value, err := readOrderedJSON(dec)
			if err != nil {
				return nil, err
			}
			obj = obj.set(key, value)
		}
		_, err = dec.Token()
		return obj, err
	case '[':
		arr := []interface{}{}
		for dec.More() {
			value, err := readOrderedJSON(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, value)
		}
		_, err = dec.Token()
		return arr, err
	}
	return nil, errors.New("altcha: unexpected JSON delimiter")
}

// set assigns key like JSON.parse: a duplicate key keeps its first position
// and takes the last value.
func (o orderedObject) set(key string, value interface{}) orderedObject {
	for i := range o {
		if o[i].key == key {
			o[i].value = value
			return o
		}
	}
	return append(o, orderedMember{key, value})
}

// appendCanonical appends v as JSON.stringify would. sortKeys is false below
// arrays, where JS sortKeys leaves objects as they are.
func appendCanonical(buf []byte, v interface{}, sortKeys bool) []byte {
	switch val := v.(type) {
	case nil:
		return append(buf, "null"...)
	case bool:
		return strconv.AppendBool(buf, val)
	case string:
		return appendJSString(buf, val)
	case json.Number:
		return appendJSNumber(buf, val)
	case []interface{}:
		buf = append(buf, '[')
		for i, item := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = appendCanonical(buf, item, false)
		}
		return append(buf, ']')
	case orderedObject:
		sort.SliceStable(val, func(i, j int) bool {
			return jsKeyLess(val[i].key, val[j].key, sortKeys)
		})
		buf = append(buf, '{')
		for i, m := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = appendJSString(buf, m.key)
			buf = append(buf, ':')
			buf = appendCanonical(buf, m.value, sortKeys)
		}
		return append(buf, '}')
	}
	return buf
}

// jsKeyLess orders keys as a JS object enumerates them: array-index keys
// first in numeric order, then the others in insertion order, which for
// sortKeys is Array.prototype.sort order (UTF-16 code units).
func jsKeyLess(a, b string, sortKeys bool) bool {
	ai, aIndex := jsArrayIndex(a)
	bi, bIndex := jsArrayIndex(b)
	switch {
	case aIndex && bIndex:
		return ai < bi
	case aIndex != bIndex:
		return aIndex
	case sortKeys:
		return utf16Less(a, b)
	}
	return false
}

// jsArrayIndex reports whether s is a canonical array index
// ("0".."4294967294" without leading zeros).
func jsArrayIndex(s string) (uint32, bool) {
	if s == "" || len(s) > 10 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == math.MaxUint32 {
		return 0, false
	}
	return uint32(n), true
}

// utf16Less compares strings by UTF-16 code units, like JS string comparison.
func utf16Less(a, b string) bool {
	for a != "" && b != "" {
		ra, na := utf8.DecodeRuneInString(a)
		rb, nb := utf8.DecodeRuneInString(b)
		if ra != rb {
			ha, la := utf16Units(ra)
			hb, lb := utf16Units(rb)
			if ha != hb {
				return ha < hb
			}
			return la < lb
		}
		a, b = a[na:], b[nb:]
	}
	return a == "" && b != ""
}

func utf16Units(r rune) (rune, rune) {
	if r >= 0x10000 {
		return utf16.EncodeRune(r)
	}
	return r, 0
}

// appendJSString appends s quoted as JSON.stringify does: only '"', '\\' and
// control characters are escaped.
func appendJSString(buf []byte, s string) []byte {
	const hex = "0123456789abcdef"
	buf = append(buf, '"')
	start := 0
	for i := range len(s) {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		buf = append(buf, s[start:i]...)
		switch c {
		case '"', '\\':
			buf = append(buf, '\\', c)
		case '\b':
			buf = append(buf, '\\', 'b')
		case '\f':
			buf = append(buf, '\\', 'f')
		case '\n':
			buf = append(buf, '\\', 'n')
		case '\r':
			buf = append(buf, '\\', 'r')
		case '\t':
			buf = append(buf, '\\', 't')
		default:
			buf = append(buf, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		}
		start = i + 1
	}
	buf = append(buf, s[start:]...)
	return append(buf, '"')
}

// appendJSNumber appends n as JSON.stringify formats the double it parses to.
func appendJSNumber(buf []byte, n json.Number) []byte {
	f, _ := strconv.ParseFloat(n.String(), 64)
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return append(buf, "null"...)
	}
	if f == 0 {
		return append(buf, '0') // also -0
	}
	format := byte('f')
	if abs := math.Abs(f); abs < 1e-6 || abs >= 1e21 {
		format = 'e'
	}
	buf = strconv.AppendFloat(buf, f, format, -1, 64)
	if format == 'e' {
		// Go writes e-07 where JS writes e-7.
		if n := len(buf); n >= 4 && buf[n-4] == 'e' && buf[n-3] == '-' && buf[n-2] == '0' {
			buf[n-2] = buf[n-1]
			buf = buf[:n-1]
		}
	}
	return buf
}

// UnmarshalJSON decodes the parameters and keeps the raw "data" value, so a
// challenge created by another implementation re-encodes (and verifies) with
// its original nested key order.
func (p *ChallengeParameters) UnmarshalJSON(b []byte) error {
	type plain ChallengeParameters
	var aux struct {
		plain
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*p = ChallengeParameters(aux.plain)
	p.Data, p.rawData = nil, aux.Data
	if aux.Data != nil {
		if err := json.Unmarshal(aux.Data, &p.Data); err != nil {
			return err
		}
	}
	return nil
}

// MarshalJSON encodes the parameters, emitting the "data" value received by
// UnmarshalJSON as long as Data still holds the same values.
func (p ChallengeParameters) MarshalJSON() ([]byte, error) {
	type plain ChallengeParameters
	data, err := p.dataJSON()
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		plain
		Data json.RawMessage `json:"data,omitempty"`
	}{plain(p), data})
}

func (p ChallengeParameters) dataJSON() (json.RawMessage, error) {
	if p.rawData != nil {
		fresh, err := json.Marshal(p.Data)
		if err != nil {
			return nil, err
		}
		if sameJSON(p.rawData, fresh) {
			return p.rawData, nil
		}
	}
	if len(p.Data) == 0 {
		return nil, nil
	}
	return json.Marshal(p.Data)
}

// sameJSON reports whether a and b decode to equal values, ignoring key order.
func sameJSON(a, b []byte) bool {
	var va, vb interface{}
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}
