package altcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultVerifyServerTimeout    = 10 * time.Second
	defaultVerifyServerRetryDelay = 300 * time.Millisecond
)

// RetryBackoff controls how the delay between VerifyServer retry attempts grows.
type RetryBackoff string

const (
	RetryBackoffFixed       RetryBackoff = "fixed"
	RetryBackoffExponential RetryBackoff = "exponential"
)

// VerifyServerOptions configures a remote verification request to the
// ALTCHA Sentinel `/v2/verify/signature` (Sentinel v2) or
// `/v1/verify/signature` (Sentinel v1, and the Sentinel v2 `/v1` alias) API.
type VerifyServerOptions struct {
	// URL is the full Sentinel verify endpoint:
	// "https://sentinel.example.com/v2/verify/signature" (Sentinel v2) or
	// "https://sentinel.example.com/v1/verify/signature" (Sentinel v1).
	URL string
	// Payload is the payload received from the client (POST /v2/verify),
	// typically the raw base64 string, but any JSON-marshalable value is accepted.
	Payload interface{}
	// APIKey is, for Sentinel v2, the id of a restricted or full API key of the
	// account that owns the payload's API key. When set, the request is
	// authenticated with HTTP Basic APIKey:Secret and Secret is not sent in the
	// body, as /v2/verify/signature requires. Leave empty for Sentinel v1.
	APIKey string
	// Secret is the API key secret. With APIKey (Sentinel v2), the secret of
	// that key, sent as the Basic password; required. Without APIKey
	// (Sentinel v1), optional and sent as "secret" in the body: Sentinel checks
	// it matches the payload's API key.
	Secret string
	// HTTPClient performs the requests. Defaults to http.DefaultClient.
	HTTPClient *http.Client
	// Headers are additional headers sent with each request. An Authorization
	// header is replaced when APIKey is set.
	Headers map[string]string
	// Timeout bounds each individual attempt. Defaults to 10s.
	Timeout time.Duration
	// Retries is the number of retry attempts after the first try. Defaults to 0.
	Retries int
	// RetryDelay is the base delay between retries. Defaults to 300ms.
	RetryDelay time.Duration
	// RetryBackoff controls how RetryDelay grows between attempts. Defaults to RetryBackoffExponential.
	RetryBackoff RetryBackoff
}

// VerifyServerResult is the outcome of a remote Sentinel verification request.
type VerifyServerResult struct {
	Verified bool `json:"verified"`
	// Reason is why Sentinel rejected the payload, e.g. PAYLOAD_ALREADY_USED,
	// INVALID_PAYLOAD, API_KEY_NOT_ALLOWED (v2) or WRONG_API_KEY_SECRET (v1);
	// for an HTTP 400 response, its "error".
	Reason           string                           `json:"reason,omitempty"`
	APIKey           string                           `json:"apiKey,omitempty"`
	VerificationData *ServerSignatureVerificationData `json:"verificationData,omitempty"`
}

// HTTPStatusError is returned when Sentinel responds with an unexpected
// (non-2xx, non-400) HTTP status, e.g. Sentinel v2's 401/403 for missing or
// wrong credentials. Use errors.As to inspect it.
type HTTPStatusError struct {
	StatusCode int
	Status     string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("altcha: unexpected HTTP status %s", e.Status)
}

// VerifyServer verifies a payload remotely via the ALTCHA Sentinel
// `/v2/verify/signature` (with options.APIKey) or `/v1/verify/signature` API,
// retrying on transport failures according to
// options.Retries/RetryDelay/RetryBackoff.
//
// A definitive verdict from Sentinel (including an HTTP 400 rejection) is
// returned as (VerifyServerResult, nil); the verdict itself is carried in
// Result.Verified/Result.Reason. Any other 4xx status (e.g. Sentinel v2's
// 401/403 for missing or wrong credentials, or 429) fails at once without
// retrying. A network error, other unexpected HTTP status or context
// cancellation that survives all retries is returned as
// (VerifyServerResult{}, error); use errors.As for *HTTPStatusError, or
// errors.Is for context errors.
func VerifyServer(ctx context.Context, options VerifyServerOptions) (VerifyServerResult, error) {
	if options.URL == "" {
		return VerifyServerResult{}, fmt.Errorf("altcha: URL parameter is required")
	}
	if options.APIKey != "" && options.Secret == "" {
		return VerifyServerResult{}, fmt.Errorf("altcha: Secret parameter is required when APIKey is set")
	}

	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultVerifyServerTimeout
	}
	retryDelay := options.RetryDelay
	if retryDelay <= 0 {
		retryDelay = defaultVerifyServerRetryDelay
	}
	backoff := options.RetryBackoff
	if backoff == "" {
		backoff = RetryBackoffExponential
	}

	bodySecret := options.Secret
	if options.APIKey != "" {
		bodySecret = ""
	}
	body, err := json.Marshal(struct {
		Payload interface{} `json:"payload"`
		Secret  string      `json:"secret,omitempty"`
	}{options.Payload, bodySecret})
	if err != nil {
		return VerifyServerResult{}, fmt.Errorf("altcha: failed to marshal payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= options.Retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return VerifyServerResult{}, fmt.Errorf("altcha: verify server request aborted: %w", err)
		}

		result, err := doVerifyServerAttempt(ctx, client, options, body, timeout)
		if err == nil {
			return result, nil
		}
		var statusErr *HTTPStatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode >= 400 && statusErr.StatusCode < 500 {
			return VerifyServerResult{}, fmt.Errorf("altcha: verify server request rejected: %w", err)
		}
		lastErr = err

		if attempt >= options.Retries {
			break
		}

		delay := retryDelay
		if backoff == RetryBackoffExponential {
			delay = retryDelay * time.Duration(int64(1)<<uint(attempt))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return VerifyServerResult{}, fmt.Errorf("altcha: verify server request aborted: %w", ctx.Err())
		case <-timer.C:
		}
	}

	return VerifyServerResult{}, fmt.Errorf("altcha: verify server request failed after %d attempt(s): %w", options.Retries+1, lastErr)
}

// doVerifyServerAttempt performs a single HTTP round trip. A nil error means
// a definitive verdict was obtained (including an HTTP 400 rejection); a
// non-nil error means the attempt failed (retryable unless a 4xx status).
func doVerifyServerAttempt(ctx context.Context, client *http.Client, options VerifyServerOptions, body []byte, timeout time.Duration) (VerifyServerResult, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, options.URL, bytes.NewReader(body))
	if err != nil {
		return VerifyServerResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range options.Headers {
		req.Header.Set(k, v)
	}
	if options.APIKey != "" {
		req.SetBasicAuth(options.APIKey, options.Secret)
	}

	resp, err := client.Do(req)
	if err != nil {
		return VerifyServerResult{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return VerifyServerResult{}, err
	}

	if resp.StatusCode == http.StatusBadRequest {
		var errBody struct {
			Error string `json:"error"`
		}
		reason := fmt.Sprintf("HTTP_%d", resp.StatusCode)
		if json.Unmarshal(respBody, &errBody) == nil && errBody.Error != "" {
			reason = errBody.Error
		}
		return VerifyServerResult{Verified: false, Reason: reason}, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return VerifyServerResult{}, &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
	}

	var result VerifyServerResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return VerifyServerResult{}, fmt.Errorf("altcha: failed to decode response: %w", err)
	}
	return result, nil
}
