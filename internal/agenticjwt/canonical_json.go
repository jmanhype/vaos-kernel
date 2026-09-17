package agenticjwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// canonicalJSON serializes an I-JSON value using RFC 8785 JCS. The value is
// first passed through encoding/json so structs and typed maps follow the same
// conversion rules used by the public API; the resulting generic JSON value is
// then serialized with RFC 8785 string, number, array, and property ordering.
func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if err := validateIJSON(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}

	var output bytes.Buffer
	if err := encodeCanonicalJSON(&output, generic); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func encodeCanonicalJSON(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		if err := encodeCanonicalJSONString(output, typed); err != nil {
			return err
		}
	case json.Number:
		encoded, err := canonicalJSONNumber(typed)
		if err != nil {
			return err
		}
		output.WriteString(encoded)
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := encodeCanonicalJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		if err := encodeCanonicalJSONObject(output, typed); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func encodeCanonicalJSONObject(output *bytes.Buffer, object map[string]any) error {
	type canonicalKey struct {
		name  string
		units []uint16
	}
	keys := make([]canonicalKey, 0, len(object))
	for key := range object {
		units, err := utf16CodeUnits(key)
		if err != nil {
			return err
		}
		keys = append(keys, canonicalKey{name: key, units: units})
	}
	sort.Slice(keys, func(i, j int) bool {
		return compareUTF16(keys[i].units, keys[j].units) < 0
	})

	output.WriteByte('{')
	for index, key := range keys {
		if index > 0 {
			output.WriteByte(',')
		}
		if err := encodeCanonicalJSONString(output, key.name); err != nil {
			return err
		}
		output.WriteByte(':')
		if err := encodeCanonicalJSON(output, object[key.name]); err != nil {
			return err
		}
	}
	output.WriteByte('}')
	return nil
}

func encodeCanonicalJSONString(output *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("canonical JSON strings must be valid UTF-8")
	}
	output.WriteByte('"')
	for index := 0; index < len(value); {
		r, size := utf8.DecodeRuneInString(value[index:])
		switch {
		case r == '"':
			output.WriteString(`\"`)
		case r == '\\':
			output.WriteString(`\\`)
		case r == '\b':
			output.WriteString(`\b`)
		case r == '\t':
			output.WriteString(`\t`)
		case r == '\n':
			output.WriteString(`\n`)
		case r == '\f':
			output.WriteString(`\f`)
		case r == '\r':
			output.WriteString(`\r`)
		case r <= 0x1f:
			fmt.Fprintf(output, `\u%04x`, r)
		default:
			output.WriteString(value[index : index+size])
		}
		index += size
	}
	output.WriteByte('"')
	return nil
}

// validateIJSON checks the RFC 7493 constraints that encoding/json otherwise
// makes lossy before decoding. In particular, escaped lone surrogates are
// replaced with U+FFFD rather than rejected.
func validateIJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("canonical JSON input must be valid UTF-8")
	}

	inString := false
	escaped := false
	pendingHighSurrogate := false
	for index := 0; index < len(raw); {
		item := raw[index]
		if !inString {
			if item == '"' {
				inString = true
				pendingHighSurrogate = false
			}
			index++
			continue
		}

		if escaped {
			if item != 'u' {
				if pendingHighSurrogate {
					return fmt.Errorf("canonical JSON contains a lone high surrogate")
				}
				pendingHighSurrogate = false
				escaped = false
				index++
				continue
			}
			if index+5 > len(raw) {
				return fmt.Errorf("canonical JSON contains a truncated Unicode escape")
			}
			unit, err := parseHex16(raw[index+1 : index+5])
			if err != nil {
				return err
			}
			switch {
			case unit >= 0xd800 && unit <= 0xdbff:
				if pendingHighSurrogate {
					return fmt.Errorf("canonical JSON contains adjacent high surrogates")
				}
				pendingHighSurrogate = true
			case unit >= 0xdc00 && unit <= 0xdfff:
				if !pendingHighSurrogate {
					return fmt.Errorf("canonical JSON contains a lone low surrogate")
				}
				pendingHighSurrogate = false
			default:
				pendingHighSurrogate = false
			}
			escaped = false
			index += 5
			continue
		}

		switch item {
		case '\\':
			escaped = true
		case '"':
			if pendingHighSurrogate {
				return fmt.Errorf("canonical JSON contains a lone high surrogate")
			}
			inString = false
		case '\b', '\t', '\n', '\f', '\r':
			return fmt.Errorf("canonical JSON contains an unescaped control character")
		default:
			if pendingHighSurrogate {
				return fmt.Errorf("canonical JSON contains a lone high surrogate")
			}
			if item < 0x20 {
				return fmt.Errorf("canonical JSON contains an unescaped control character")
			}
			pendingHighSurrogate = false
		}
		index++
	}
	if inString || escaped {
		return fmt.Errorf("canonical JSON contains an unterminated string")
	}
	return nil
}

func parseHex16(value []byte) (uint16, error) {
	var unit uint16
	for _, item := range value {
		var digit uint16
		switch {
		case item >= '0' && item <= '9':
			digit = uint16(item - '0')
		case item >= 'a' && item <= 'f':
			digit = uint16(item-'a') + 10
		case item >= 'A' && item <= 'F':
			digit = uint16(item-'A') + 10
		default:
			return 0, fmt.Errorf("canonical JSON contains an invalid Unicode escape")
		}
		unit = unit<<4 | digit
	}
	return unit, nil
}

func canonicalJSONNumber(number json.Number) (string, error) {
	value, err := strconv.ParseFloat(number.String(), 64)
	if err != nil {
		return "", err
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "", fmt.Errorf("canonical JSON numbers must be finite")
	}
	return formatECMAScriptNumber(value), nil
}

// formatECMAScriptNumber implements the RFC 8785 subset of ECMAScript
// Number::toString: shortest round-trip digits, fixed notation for
// 1e-6 <= abs(value) < 1e21, and compact scientific notation otherwise.
func formatECMAScriptNumber(value float64) string {
	if value == 0 {
		return "0"
	}

	negative := false
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	if strings.HasPrefix(scientific, "-") {
		negative = true
		scientific = scientific[1:]
	}
	mantissa, exponentText, _ := strings.Cut(scientific, "e")
	exponent, err := strconv.Atoi(exponentText)
	if err != nil {
		// strconv.FormatFloat always emits a valid exponent. Keep the failure
		// path explicit rather than panicking on future format changes.
		return strconv.FormatFloat(value, 'g', -1, 64)
	}

	var result string
	switch {
	case exponent >= -6 && exponent < 21:
		result = fixedDecimal(mantissa, exponent)
	default:
		sign := "+"
		if exponent < 0 {
			sign = "-"
			exponent = -exponent
		}
		result = mantissa + "e" + sign + strconv.Itoa(exponent)
	}
	if negative {
		return "-" + result
	}
	return result
}

func fixedDecimal(mantissa string, exponent int) string {
	integerDigits, fractionDigits, _ := strings.Cut(mantissa, ".")
	digits := integerDigits + fractionDigits
	point := exponent + 1

	switch {
	case point >= len(digits):
		digits += strings.Repeat("0", point-len(digits))
	case point > 0:
		digits = digits[:point] + "." + digits[point:]
	default:
		digits = "0." + strings.Repeat("0", -point) + digits
	}
	return digits
}

func utf16CodeUnits(value string) ([]uint16, error) {
	units := make([]uint16, 0, utf8.RuneCountInString(value))
	for index := 0; index < len(value); {
		r, size := utf8.DecodeRuneInString(value[index:])
		switch {
		case r == utf8.RuneError && size == 1, r >= 0xd800 && r <= 0xdfff:
			return nil, fmt.Errorf("canonical JSON strings must contain valid Unicode scalar values")
		case r <= 0xffff:
			units = append(units, uint16(r))
		default:
			offset := r - 0x10000
			units = append(units, uint16(0xd800+(offset>>10)), uint16(0xdc00+(offset&0x3ff)))
		}
		index += size
	}
	return units, nil
}

func compareUTF16(left, right []uint16) int {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	for index := 0; index < limit; index++ {
		if left[index] != right[index] {
			if left[index] < right[index] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(left) < len(right):
		return -1
	case len(left) > len(right):
		return 1
	default:
		return 0
	}
}
