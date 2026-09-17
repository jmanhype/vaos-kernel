package agenticjwt

import (
	"bytes"
	"encoding/json"
)

func decodeTestJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}
