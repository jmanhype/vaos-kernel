package agenticjwt

import (
	"encoding/json"
	"math"
	"testing"
)

func TestCanonicalJSONRFC8785Sample(t *testing.T) {
	input := `{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"€$\u000f\nA'B\"\\\"/","literals":[null,true,false]}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\"/"}`

	encoded, err := canonicalJSON(json.RawMessage(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != want {
		t.Fatalf("canonical JSON = %s\nwant               %s", encoded, want)
	}
}

func TestCanonicalJSONRFC8785NumberVectors(t *testing.T) {
	tests := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, test := range tests {
		value := math.Float64frombits(test.bits)
		encoded, err := canonicalJSON(value)
		if err != nil {
			t.Fatalf("bits %016x: %v", test.bits, err)
		}
		if string(encoded) != test.want {
			t.Fatalf("bits %016x canonical number = %s, want %s", test.bits, encoded, test.want)
		}
	}
}

func TestCanonicalJSONRFC8785SortsPropertyNamesAsUTF16CodeUnits(t *testing.T) {
	input := "{\"\\uffff\":1,\"\\ud800\\udc00\":2}"
	want := "{\"𐀀\":2,\"￿\":1}"

	encoded, err := canonicalJSON(json.RawMessage(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != want {
		t.Fatalf("canonical JSON = %s, want %s", encoded, want)
	}
}

func TestCanonicalJSONRFC8785InvalidNumbers(t *testing.T) {
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := canonicalJSON(value); err == nil {
			t.Fatalf("accepted non-finite number %v", value)
		}
	}
}

func TestCanonicalJSONRFC8785RejectsLoneSurrogate(t *testing.T) {
	input := `{"name":"\ud800"}`
	if _, err := canonicalJSON(json.RawMessage(input)); err == nil {
		t.Fatal("accepted a lone surrogate in a JSON string")
	}
}
