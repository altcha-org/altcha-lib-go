// Command sentinel verifies form submissions remotely via ALTCHA Sentinel.
//
// There is no /challenge endpoint: point the widget's challenge URL at your
// Sentinel instance, which issues and signs the challenges. Sentinel also
// tracks used payloads, so each one verifies only once.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

func main() {
	// URL of your Sentinel instance's verify/signature endpoint.
	sentinelURL := os.Getenv("SENTINEL_URL")
	if sentinelURL == "" {
		sentinelURL = "https://sentinel.example.com/v1/verify/signature"
	}
	// API key secret, optional: Sentinel checks it against the payload's API key.
	apiKeySecret := os.Getenv("SENTINEL_API_KEY_SECRET")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /submit", handleSubmit(sentinelURL, apiKeySecret))

	addr := ":3000"
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

// corsMiddleware adds permissive CORS headers and handles preflight requests.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleSubmit verifies the Sentinel payload submitted with a form.
// The form must include an "altcha" field with the payload the widget
// received from Sentinel's POST /v1/verify.
func handleSubmit(sentinelURL string, apiKeySecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		payload := r.PostFormValue("altcha")
		if payload == "" {
			http.Error(w, "missing altcha field", http.StatusBadRequest)
			return
		}

		result, err := altcha.VerifyServer(r.Context(), altcha.VerifyServerOptions{
			URL:     sentinelURL,
			Payload: payload,
			Secret:  apiKeySecret,
			Timeout: 10 * time.Second,
			Retries: 2,
		})
		if err != nil {
			// Sentinel could not be reached; no verdict was given.
			http.Error(w, "verification unavailable", http.StatusBadGateway)
			log.Printf("VerifyServer error: %v", err)
			return
		}

		if !result.Verified {
			http.Error(w, "verification failed: "+result.Reason, http.StatusUnprocessableEntity)
			return
		}

		// When Sentinel classified form fields, it signs a hash of their values.
		// Reject the submission if they were changed after verification.
		data := result.VerificationData
		if data != nil && data.FieldsHash != "" {
			ok, err := altcha.VerifyFieldsHash(r.PostForm, data.Fields, data.FieldsHash, altcha.SHA256)
			if err != nil || !ok {
				http.Error(w, "form fields were modified", http.StatusUnprocessableEntity)
				return
			}
		}

		if data != nil && data.Location != nil {
			log.Printf("submission %s: classification=%s country=%s", data.Id, data.Classification, data.Location.CountryCode)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"altcha": result,
			"body":   r.PostForm,
		})
	}
}
