package grpc

import (
	"encoding/json"

	grpcencoding "google.golang.org/grpc/encoding"
)

const jsonCodecName = "json"

type jsonCodec struct{}

func (jsonCodec) Name() string {
	return jsonCodecName
}

func (jsonCodec) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func init() {
	grpcencoding.RegisterCodec(jsonCodec{})
}

