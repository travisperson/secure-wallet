package jwtutil

// functions are partly or wholey lifted from https://github.com/gbrlsnchs/jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

	"github.com/gbrlsnchs/jwt/v3"
)

// DecodePayload is a useful fucntion for inspecting a jwt that is not included in the jwt
// library
func DecodePayload(token []byte, payload interface{}) error {
	sep1 := bytes.IndexByte(token, '.')
	if sep1 < 0 {
		return jwt.ErrMalformed
	}

	cbytes := token[sep1+1:]
	sep2 := bytes.IndexByte(cbytes, '.')
	if sep2 < 0 {
		return jwt.ErrMalformed
	}

	rawPayload := token[sep1+1 : sep1+1+sep2]

	pb, err := decodeToBytes(rawPayload)
	if err != nil {
		return err
	}

	if !isJSONObject(pb) {
		return jwt.ErrNotJSONObject
	}

	if err = json.Unmarshal(pb, payload); err != nil {
		return err
	}

	return nil
}

func decodeToBytes(enc []byte) ([]byte, error) {
	encoding := base64.RawURLEncoding
	dec := make([]byte, encoding.DecodedLen(len(enc)))
	if _, err := encoding.Decode(dec, enc); err != nil {
		return nil, err
	}
	return dec, nil
}

func isJSONObject(payload []byte) bool {
	payload = bytes.TrimSpace(payload)
	return payload[0] == '{' && payload[len(payload)-1] == '}'
}
