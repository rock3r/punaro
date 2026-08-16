package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func decodeStrict[T any](body []byte, limit int) (T, error) {
	var zero T
	if len(body) == 0 || len(body) > limit {
		return zero, errors.New("release document is invalid")
	}
	if err := rejectDuplicateFields(body); err != nil {
		return zero, errors.New("release document is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return zero, errors.New("release document is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return zero, errors.New("release document is invalid")
	}
	return value, nil
}

func encodeDocument(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	body := buf.Bytes()
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return nil, errors.New("release document is invalid")
	}
	return body[:len(body)-1], nil
}
