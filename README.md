# ALTCHA Go Library

The ALTCHA Go Library is a lightweight library for creating and verifying [ALTCHA](https://altcha.org) challenges in Go applications. It implements the ALTCHA v2 proof-of-work protocol based on key derivation functions (KDF).

## Compatibility

- Go 1.22+

## Installation

```sh
go get github.com/altcha-org/altcha-lib-go/v2
```

## Packages

| Package | Import path | Description |
|---|---|---|
| v2 (default) | `github.com/altcha-org/altcha-lib-go/v2` | ALTCHA v2 PoW protocol |
| v1 (legacy) | `github.com/altcha-org/altcha-lib-go` | Legacy ALTCHA v1 protocol |

## Usage

### Create a challenge

```go
import altcha "github.com/altcha-org/altcha-lib-go/v2"

challenge, err := altcha.CreateChallenge(altcha.CreateChallengeOptions{
    Algorithm:           "PBKDF2/SHA-256",
    DeriveKey:           altcha.DeriveKeyPBKDF2(),
    HMACSignatureSecret: "your-secret",
    Cost:                5000,
    KeyLength:           32,
})
```

### Solve a challenge

```go
solution, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{
    Challenge: challenge,
    DeriveKey: altcha.DeriveKeyPBKDF2(),
})
```

### Verify a solution

```go
result, err := altcha.VerifySolution(altcha.VerifySolutionOptions{
    Challenge:           payload.Challenge,
    Solution:            payload.Solution,
    DeriveKey:           altcha.DeriveKeyPBKDF2(),
    HMACSignatureSecret: "your-secret",
})

if result.Verified {
    // valid
}
```

### Remote verification (Sentinel)

Verify a payload remotely via the ALTCHA Sentinel API instead of verifying locally. Both Sentinel v2 (`/v2/verify/signature`) and Sentinel v1 (`/v1/verify/signature`) are supported; the version is selected by `URL` and whether `APIKey` is set. Timeout and retries are configurable per call.

#### Sentinel v2

Sentinel v2 authenticates the request with a `restricted` or `full` API key of the account that owns the payload's (public) key. Set `APIKey` and `Secret` to its id and secret: they are sent as HTTP Basic credentials, and nothing is sent as `secret` in the body. `APIKey` without `Secret` returns an error before any request is sent.

```go
result, err := altcha.VerifyServer(ctx, altcha.VerifyServerOptions{
    URL:          "https://sentinel.example.com/v2/verify/signature",
    Payload:      payload,   // raw payload string from POST /v2/verify
    APIKey:       "key_...", // restricted or full API key
    Secret:       "sec_...", // its secret
    Timeout:      5 * time.Second,
    Retries:      2,
    RetryBackoff: altcha.RetryBackoffExponential,
})
if err != nil {
    // transport failure: network error, unexpected HTTP status (e.g. 401/403), or ctx cancellation
}
if result.Verified {
    // valid
}
```

#### Sentinel v1

For Sentinel v1 (and the `/v1/verify/signature` alias Sentinel v2 serves with `v1_compat`), leave `APIKey` empty. `Secret` is optional: it is sent as `secret` in the body, and Sentinel checks that it is the secret of the payload's API key (`WRONG_API_KEY_SECRET` otherwise).

```go
result, err := altcha.VerifyServer(ctx, altcha.VerifyServerOptions{
    URL:          "https://sentinel.example.com/v1/verify/signature",
    Payload:      payload,               // raw payload string from POST /v1/verify
    Secret:       "your-api-key-secret", // optional
    Timeout:      5 * time.Second,
    Retries:      2,
    RetryBackoff: altcha.RetryBackoffExponential,
})
if err != nil {
    // transport failure: network error, unexpected HTTP status, or ctx cancellation
}
if result.Verified {
    // valid
}
```

#### Results and errors

A definitive verdict from Sentinel (including a rejection, e.g. `PAYLOAD_ALREADY_USED`, `INVALID_PAYLOAD`, `API_KEY_NOT_ALLOWED` (v2: the payload belongs to another account than `APIKey`) or `WRONG_API_KEY_SECRET` (v1), and an HTTP 400 response) is returned as `(VerifyServerResult, nil)`; check `result.Verified`/`result.Reason`. Other 4xx statuses (e.g. Sentinel v2's `401`/`403` for missing, wrong or `public` credentials, `429`) are not retried and are returned as an `error` at once. A network error or other unexpected status that survives all retries is returned as an `error` too — use `errors.As` for `*altcha.HTTPStatusError`, or `errors.Is` for context errors.

`result.VerificationData` decodes both versions' response. `ChallengeAlgorithm` is filled from v1's `challengeAlgorithm` or v2's `challenge.algorithm`. Sentinel v2's other new keys (`challenge.issued`, `challenge.protectionLevel`, `his.automation`, `device.os`, `ip.countryCode`, …) are in `VerificationData.Extra`, keyed by their dotted name.

See [`examples/sentinel`](./v2/examples/sentinel) for an HTTP server with a `POST /submit` endpoint that verifies Sentinel payloads this way, with either version.

### HTTP server example

See [`examples/server`](./v2/examples/server) for a minimal HTTP server with `GET /challenge` and `POST /submit` endpoints.

## Key derivation algorithms

Choose the algorithm that fits your performance and security requirements. All algorithms accept a `Cost` parameter that controls the work factor.

### PBKDF2 (`DeriveKeyPBKDF2`)

**Recommended**. Password-Based Key Derivation Function 2. Moderate cost, widely supported.

| Algorithm | Description |
|---|---|
| `PBKDF2/SHA-256` | PBKDF2 with SHA-256, default |
| `PBKDF2/SHA-384` | PBKDF2 with SHA-384 |
| `PBKDF2/SHA-512` | PBKDF2 with SHA-512 |

```go
altcha.CreateChallenge(altcha.CreateChallengeOptions{
    Algorithm: "PBKDF2/SHA-256",
    DeriveKey: altcha.DeriveKeyPBKDF2(),
    Cost:      5000, // iterations
})
```

### Scrypt (`DeriveKeyScrypt`)

Memory-hard KDF. `Cost` maps to N, `MemoryCost` to r, `Parallelism` to p.

```go
altcha.CreateChallenge(altcha.CreateChallengeOptions{
    Algorithm:   "Scrypt",
    DeriveKey:   altcha.DeriveKeyScrypt(),
    Cost:        65536,
    MemoryCost:  8,
    Parallelism: 1,
})
```

### Argon2id (`DeriveKeyArgon2id`)

Memory-hard KDF, winner of the Password Hashing Competition. `Cost` maps to time (iterations), `MemoryCost` to memory in KiB, `Parallelism` to threads.

```go
altcha.CreateChallenge(altcha.CreateChallengeOptions{
    Algorithm:   "Argon2id",
    DeriveKey:   altcha.DeriveKeyArgon2id(),
    Cost:        1,
    MemoryCost:  65536,
    Parallelism: 1,
})
```

### SHA (`DeriveKeySHA`)

Legacy algorithm. Iterated SHA hashing - fast, suitable for low-friction challenges.

| Algorithm | Description |
|---|---|
| `SHA-256` | SHA-256, default |
| `SHA-384` | SHA-384 |
| `SHA-512` | SHA-512 |

```go
altcha.CreateChallenge(altcha.CreateChallengeOptions{
    Algorithm: "SHA-256",
    DeriveKey: altcha.DeriveKeySHA(),
    Cost:      5000, // number of iterations
})
```

## API

### `CreateChallenge(options CreateChallengeOptions) (Challenge, error)`

Creates a new v2 challenge.

| Field | Type | Description |
|---|---|---|
| `Algorithm` | `string` | KDF algorithm name (required) |
| `DeriveKey` | `DeriveKeyFunc` | Key derivation function (required when `Counter` is set) |
| `HMACSignatureSecret` | `string` | Secret used to sign the challenge |
| `HMACKeySignatureSecret` | `string` | Optional secret to sign the derived key separately |
| `HMACAlgorithm` | `Algorithm` | HMAC algorithm (`SHA-256` default) |
| `Cost` | `int` | Work factor / iterations (required) |
| `KeyLength` | `int` | Derived key length in bytes (default: 32) |
| `KeyPrefix` | `string` | Expected key prefix the solver must match, in hex (default: `00`). Ignored when `Counter` is set. Lowercased before signing; invalid hex makes `CreateChallenge` return an error |
| `KeyPrefixLength` | `int` | Length in bytes of the key prefix derived when `Counter` is set (default: `KeyLength/2`; capped at the derived key length) |
| `Counter` | `*int` | Deterministic counter; when set, derives the key prefix from this counter |
| `CounterMode` | `CounterMode` | How the counter is appended to the nonce: `CounterModeUint32` (default, big-endian uint32) or `CounterModeString` (decimal string, for v1 compatibility). Solver and verifier must use the same mode |
| `MemoryCost` | `int` | Memory cost (Scrypt r / Argon2id KiB) |
| `Parallelism` | `int` | Parallelism (Scrypt p / Argon2id threads) |
| `ExpiresAt` | `*time.Time` | Optional challenge expiry |
| `Data` | `map[string]interface{}` | Optional arbitrary data embedded in the challenge |

### `SolveChallenge(options SolveChallengeOptions) (*Solution, error)`

Brute-forces counter values until the derived key matches the challenge prefix. Returns `nil` if stopped via `StopChan` or when `Timeout` elapses.

| Field | Type | Description |
|---|---|---|
| `Challenge` | `Challenge` | The challenge to solve |
| `DeriveKey` | `DeriveKeyFunc` | Key derivation function (must match the one used to create the challenge) |
| `CounterStart` | `int` | Starting counter value (default: 0) |
| `CounterMode` | `CounterMode` | Counter encoding (default: `CounterModeUint32`); must match the mode the challenge was created with |
| `CounterStep` | `int` | Counter increment per iteration (default: 1) |
| `StopChan` | `<-chan struct{}` | Optional channel to abort solving |
| `Timeout` | `time.Duration` | Maximum solving time (default: 90s); negative disables it |

### `VerifySolution(options VerifySolutionOptions) (VerifySolutionResult, error)`

Verifies a submitted solution against a challenge.

| Field | Type | Description |
|---|---|---|
| `Challenge` | `Challenge` | The original challenge |
| `Solution` | `Solution` | The submitted solution |
| `DeriveKey` | `DeriveKeyFunc` | Key derivation function. Required unless the challenge has a `keySignature` and `HMACKeySignatureSecret` is set; if it is missing, `VerifySolution` returns an error |
| `CounterMode` | `CounterMode` | Counter encoding (default: `CounterModeUint32`); must match the mode the challenge was created with |
| `HMACSignatureSecret` | `string` | Secret used when the challenge was signed (required; if empty, `VerifySolution` returns an error) |
| `HMACKeySignatureSecret` | `string` | Secret used for key signature verification |
| `HMACAlgorithm` | `Algorithm` | HMAC algorithm (`SHA-256` default) |

**Result fields:**

| Field | Type | Description |
|---|---|---|
| `Verified` | `bool` | `true` if the solution is valid |
| `Expired` | `bool` | `true` if the challenge has expired |
| `InvalidSignature` | `*bool` | `nil` if not checked; `true` if signature is invalid |
| `InvalidSolution` | `*bool` | `nil` if not checked; `true` if derived key does not match |
| `Time` | `int64` | Verification time in milliseconds |

### Types

```go
type Challenge struct {
    Parameters ChallengeParameters `json:"parameters"`
    Signature  string              `json:"signature,omitempty"`
}

type ChallengeParameters struct {
    Algorithm    string                 `json:"algorithm"`
    Nonce        string                 `json:"nonce"`
    Salt         string                 `json:"salt"`
    Cost         int                    `json:"cost"`
    KeyLength    int                    `json:"keyLength"`
    KeyPrefix    string                 `json:"keyPrefix"`
    KeySignature string                 `json:"keySignature,omitempty"`
    MemoryCost   int                    `json:"memoryCost,omitempty"`
    Parallelism  int                    `json:"parallelism,omitempty"`
    ExpiresAt    int64                  `json:"expiresAt,omitempty"`
    Data         map[string]interface{} `json:"data,omitempty"`
}

type Solution struct {
    Counter    int    `json:"counter"`
    DerivedKey string `json:"derivedKey"`
    Time       int64  `json:"time,omitempty"`
}

type Payload struct {
    Challenge Challenge `json:"challenge"`
    Solution  Solution  `json:"solution"`
}

type DeriveKeyFunc func(params ChallengeParameters, salt []byte, password []byte) ([]byte, error)
```

## v1 (legacy)

The original ALTCHA v1 protocol (SHA-based hash challenge) is available at `github.com/altcha-org/altcha-lib-go` (no version suffix):

```go
import altcha "github.com/altcha-org/altcha-lib-go"

challenge, err := altcha.CreateChallenge(altcha.ChallengeOptions{
    HMACKey:   "secret",
    MaxNumber: 100000,
})

ok, err := altcha.VerifySolution(payload, "secret", true)

// Distinguish an expired challenge from an invalid solution:
result, err := altcha.VerifySolutionWithResult(payload, "secret", true)
if result.Expired {
    // ask the client to fetch a new challenge
}
```

## License

MIT
