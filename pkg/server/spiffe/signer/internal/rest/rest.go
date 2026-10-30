// Package rest holds the small JSON-over-HTTP helper the KMS signers share.
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxBody bounds how much of a response is read, so a misbehaving endpoint
// cannot exhaust memory.
const maxBody = 1 << 20

// Do sends body, as JSON unless headers set another Content-Type, and decodes a
// 2xx JSON response into out. Non-2xx responses become errors that include the
// start of the body.
func Do(ctx context.Context, client *http.Client, method, url string, headers map[string]string, body io.Reader, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, redact(url), err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("%s %s: reading response: %w", method, redact(url), err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet := strings.TrimSpace(string(data))
		if len(snippet) > 512 {
			snippet = snippet[:512] + "..."
		}
		return fmt.Errorf("%s %s: HTTP %d: %s", method, redact(url), resp.StatusCode, snippet)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: decoding response: %w", method, redact(url), err)
	}
	return nil
}

// JSONBody encodes v for Do.
func JSONBody(v interface{}) (io.Reader, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

// redact drops the query string, which may carry API versions today but must
// never leak anything sensitive into logs if that changes.
func redact(url string) string {
	if i := strings.IndexByte(url, '?'); i >= 0 {
		return url[:i]
	}
	return url
}
