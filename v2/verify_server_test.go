package altcha

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyServer(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		var gotBody map[string]interface{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
			}
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("failed to decode request body: %v", err)
			}
			json.NewEncoder(w).Encode(VerifyServerResult{Verified: true, APIKey: "key_123"})
		}))
		defer server.Close()

		result, err := VerifyServer(context.Background(), VerifyServerOptions{
			URL:     server.URL,
			Payload: "payload-string",
			Secret:  "shh",
		})
		if err != nil {
			t.Fatalf("VerifyServer() error = %v", err)
		}
		if !result.Verified {
			t.Error("expected Verified = true")
		}
		if result.APIKey != "key_123" {
			t.Errorf("expected APIKey = key_123, got %s", result.APIKey)
		}
		if gotBody["payload"] != "payload-string" || gotBody["secret"] != "shh" {
			t.Errorf("unexpected request body: %+v", gotBody)
		}
	})

	t.Run("CustomHeaders", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Custom") != "value" {
				t.Errorf("expected X-Custom header = value, got %s", r.Header.Get("X-Custom"))
			}
			json.NewEncoder(w).Encode(VerifyServerResult{Verified: true})
		}))
		defer server.Close()

		_, err := VerifyServer(context.Background(), VerifyServerOptions{
			URL:     server.URL,
			Payload: "p",
			Headers: map[string]string{"X-Custom": "value"},
		})
		if err != nil {
			t.Fatalf("VerifyServer() error = %v", err)
		}
	})

	t.Run("BadRequestIsDefinitiveNotRetried", func(t *testing.T) {
		var calls int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "INVALID_PAYLOAD"})
		}))
		defer server.Close()

		result, err := VerifyServer(context.Background(), VerifyServerOptions{
			URL:     server.URL,
			Payload: "p",
			Retries: 3,
		})
		if err != nil {
			t.Fatalf("VerifyServer() error = %v, want nil", err)
		}
		if result.Verified {
			t.Error("expected Verified = false")
		}
		if result.Reason != "INVALID_PAYLOAD" {
			t.Errorf("expected Reason = INVALID_PAYLOAD, got %s", result.Reason)
		}
		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Errorf("expected 1 call (no retry on 400), got %d", got)
		}
	})

	t.Run("RetriesThenSucceeds", func(t *testing.T) {
		var calls int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&calls, 1)
			if n < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(VerifyServerResult{Verified: true})
		}))
		defer server.Close()

		result, err := VerifyServer(context.Background(), VerifyServerOptions{
			URL:          server.URL,
			Payload:      "p",
			Retries:      2,
			RetryDelay:   time.Millisecond,
			RetryBackoff: RetryBackoffFixed,
		})
		if err != nil {
			t.Fatalf("VerifyServer() error = %v", err)
		}
		if !result.Verified {
			t.Error("expected Verified = true")
		}
		if got := atomic.LoadInt32(&calls); got != 3 {
			t.Errorf("expected 3 calls, got %d", got)
		}
	})

	t.Run("RetriesExhaustedReturnsError", func(t *testing.T) {
		var calls int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		_, err := VerifyServer(context.Background(), VerifyServerOptions{
			URL:        server.URL,
			Payload:    "p",
			Retries:    2,
			RetryDelay: time.Millisecond,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var statusErr *HTTPStatusError
		if !errors.As(err, &statusErr) {
			t.Fatalf("expected error to wrap *HTTPStatusError, got %v", err)
		}
		if statusErr.StatusCode != http.StatusInternalServerError {
			t.Errorf("expected StatusCode = 500, got %d", statusErr.StatusCode)
		}
		if got := atomic.LoadInt32(&calls); got != 3 {
			t.Errorf("expected 3 calls (1 + 2 retries), got %d", got)
		}
	})

	t.Run("ContextCancellationAborts", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := VerifyServer(ctx, VerifyServerOptions{
			URL:     server.URL,
			Payload: "p",
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected error to wrap context.Canceled, got %v", err)
		}
	})

	t.Run("MissingURL", func(t *testing.T) {
		_, err := VerifyServer(context.Background(), VerifyServerOptions{Payload: "p"})
		if err == nil {
			t.Fatal("expected error for missing URL, got nil")
		}
	})

	t.Run("DefaultHTTPClientUsedWhenNil", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(VerifyServerResult{Verified: true})
		}))
		defer server.Close()

		result, err := VerifyServer(context.Background(), VerifyServerOptions{
			URL:        server.URL,
			Payload:    "p",
			HTTPClient: nil,
		})
		if err != nil {
			t.Fatalf("VerifyServer() error = %v", err)
		}
		if !result.Verified {
			t.Error("expected Verified = true")
		}
	})

	t.Run("VerificationDataRoundTrips", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(VerifyServerResult{
				Verified: true,
				VerificationData: &ServerSignatureVerificationData{
					Id:       "abc123",
					Email:    "user@example.com",
					Verified: true,
				},
			})
		}))
		defer server.Close()

		result, err := VerifyServer(context.Background(), VerifyServerOptions{
			URL:     server.URL,
			Payload: "p",
		})
		if err != nil {
			t.Fatalf("VerifyServer() error = %v", err)
		}
		if result.VerificationData == nil {
			t.Fatal("expected VerificationData to be non-nil")
		}
		if result.VerificationData.Id != "abc123" {
			t.Errorf("expected Id = abc123, got %s", result.VerificationData.Id)
		}
	})
}
