package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"math/rand/v2"
	"net/http"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

func main() {
	// Use proper secrets from ENV in production
	hmacSecret := "hmac-secret"
	hmacKeySecret := "another-hmac-secret"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /challenge", handleChallenge(hmacSecret, hmacKeySecret))
	mux.HandleFunc("POST /submit", handleSubmit(hmacSecret))

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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// challengeTTL bounds how long a challenge (and so a solved payload) is
// accepted. It must cover solving plus the time to fill in the form.
const challengeTTL = 10 * time.Minute

// handleChallenge returns a new ALTCHA v2 challenge in deterministic mode.
// A random counter in [5000, 10000) is chosen.
func handleChallenge(hmacSecret string, hmacKeySecret string) http.HandlerFunc {
	deriveKey := altcha.DeriveKeyPBKDF2()
	return func(w http.ResponseWriter, r *http.Request) {
		counter := 5000 + rand.IntN(5000)
		expiresAt := time.Now().Add(challengeTTL)
		challenge, err := altcha.CreateChallenge(altcha.CreateChallengeOptions{
			Algorithm:              "PBKDF2/SHA-256",
			DeriveKey:              deriveKey,
			HMACSignatureSecret:    hmacSecret,
			HMACKeySignatureSecret: hmacKeySecret,
			Cost:                   5000,
			KeyLength:              32,
			Counter:                &counter,
			ExpiresAt:              &expiresAt,
		})
		if err != nil {
			http.Error(w, "failed to create challenge", http.StatusInternalServerError)
			log.Printf("CreateChallenge error: %v", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(challenge); err != nil {
			log.Printf("encode challenge error: %v", err)
		}
	}
}

// handleSubmit verifies the ALTCHA payload submitted with a form.
// The form must include an "altcha" field containing a base64-encoded JSON payload.
func handleSubmit(hmacSecret string) http.HandlerFunc {
	deriveKey := altcha.DeriveKeyPBKDF2()
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		altchaField := r.FormValue("altcha")
		if altchaField == "" {
			http.Error(w, "missing altcha field", http.StatusBadRequest)
			return
		}

		// The widget encodes the payload as base64 JSON.
		decoded, err := base64.StdEncoding.DecodeString(altchaField)
		if err != nil {
			http.Error(w, "invalid altcha encoding", http.StatusBadRequest)
			return
		}

		var payload altcha.Payload
		if err := json.Unmarshal(decoded, &payload); err != nil {
			http.Error(w, "invalid altcha payload", http.StatusBadRequest)
			return
		}

		result, err := altcha.VerifySolution(altcha.VerifySolutionOptions{
			Challenge:           payload.Challenge,
			Solution:            payload.Solution,
			DeriveKey:           deriveKey,
			HMACSignatureSecret: hmacSecret,
		})
		if err != nil {
			http.Error(w, "verification error", http.StatusInternalServerError)
			log.Printf("VerifySolution error: %v", err)
			return
		}

		if result.Expired {
			http.Error(w, "challenge expired", http.StatusUnprocessableEntity)
			return
		}

		if !result.Verified {
			http.Error(w, "invalid solution", http.StatusUnprocessableEntity)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"altcha": result,
		})
	}
}
