package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// Request body helpers enforce a maximum JSON payload size.

const maxJSONBodySize = 4 << 20 // 4 MiB

var errBodyTooLarge = errors.New("request body too large")

func readRequestJSON(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBodySize+1))
	if err != nil {
		return err
	}
	if len(body) > maxJSONBodySize {
		return errBodyTooLarge
	}
	return json.Unmarshal(body, v)
}
