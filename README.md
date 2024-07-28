# ALTCHA Go Library

The ALTCHA Go Library is a lightweight, zero-dependency library designed for creating and verifying [ALTCHA](https://altcha.org) challenges, specifically tailored for Go applications.

## Compatibility

This library is compatible with:

- Go 1.18+
- All major platforms (Linux, Windows, macOS)

## Example

- [Demo server](https://github.com/altcha-org/altcha-starter-go)

## Installation

To install the ALTCHA Go Library, use the following command:

```sh
go get github.com/altcha-org/altcha-lib-go
```

## Usage

Here’s a basic example of how to use the ALTCHA Go Library:

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/altcha-org/altcha-lib-go"
)

func main() {
    hmacKey := "secret hmac key"

    // Create a new challenge
    challenge, err := altcha.CreateChallenge(altcha.ChallengeOptions{
        HMACKey:   hmacKey,
        MaxNumber: 100000, // the maximum random number
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Challenge created:", challenge)

    // Example payload to verify
    payload := map[string]interface{}{
        "algorithm": challenge.Algorithm,
        "challenge": challenge.Challenge,
        "number":    12345, // Example number
        "salt":      challenge.Salt,
        "signature": challenge.Signature,
    }

    // Verify the solution
    ok, err := altcha.VerifySolution(payload, hmacKey, true)
    if err != nil {
        log.Fatal(err)
    }

    if ok {
        fmt.Println("Solution verified!")
    } else {
        fmt.Println("Invalid solution.")
    }
}
```

## API

### `CreateChallenge(options ChallengeOptions) (Challenge, error)`

Creates a new challenge for ALTCHA.

**Parameters:**

- `options ChallengeOptions`:
  - `Algorithm Algorithm`: Hashing algorithm to use (`SHA-1`, `SHA-256`, `SHA-512`, default: `SHA-256`).
  - `MaxNumber int64`: Maximum number for the random number generator (default: 1,000,000).
  - `SaltLength int`: Length of the random salt (default: 12 bytes).
  - `HMACKey string`: Required HMAC key.
  - `Salt string`: Optional salt string. If not provided, a random salt will be generated.
  - `Number int64`: Optional specific number to use. If not provided, a random number will be generated.
  - `Expires *time.Time`: Optional expiration time for the challenge.
  - `Params url.Values`: Optional URL-encoded query parameters.

**Returns:** `Challenge, error`

### `VerifySolution(payload map[string]interface{}, hmacKey string, checkExpires bool) (bool, error)`

Verifies an ALTCHA solution.

**Parameters:**

- `payload map[string]interface{}`: The solution payload to verify.
- `hmacKey string`: The HMAC key used for verification.
- `checkExpires bool`: Whether to check if the challenge has expired.

**Returns:** `bool, error`

### `ExtractParams(payload map[string]interface{}) url.Values`

Extracts URL parameters from the payload's salt.

**Parameters:**

- `payload map[string]interface{}`: The payload containing the salt.

**Returns:** `url.Values`

### `VerifyFieldsHash(formData map[string][]string, fields []string, fieldsHash string, algorithm Algorithm) (bool, error)`

Verifies the hash of form fields.

**Parameters:**

- `formData map[string][]string`: The form data to hash.
- `fields []string`: The fields to include in the hash.
- `fieldsHash string`: The expected hash value.
- `algorithm Algorithm`: Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`).

**Returns:** `bool, error`

### `VerifyServerSignature(payload interface{}, hmacKey string) (bool, ServerSignatureVerificationData, error)`

Verifies the server signature.

**Parameters:**

- `payload interface{}`: The payload to verify (string or `ServerSignaturePayload`).
- `hmacKey string`: The HMAC key used for verification.

**Returns:** `bool, ServerSignatureVerificationData, error`

### `SolveChallenge(challenge string, salt string, algorithm Algorithm, max int, start int, stopChan <-chan struct{}) (*Solution, error)`

Finds a solution to the given challenge.

**Parameters:**

- `challenge string`: The challenge hash.
- `salt string`: The challenge salt.
- `algorithm Algorithm`: Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`).
- `max int`: Maximum number to iterate to.
- `start int`: Starting number.
- `stopChan <-chan struct{}`: Channel to receive stop signals.

**Returns:** `*Solution, error`

## License

MIT
