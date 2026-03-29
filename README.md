# ALTCHA Go Library

The ALTCHA Go Library is a lightweight library for creating and verifying [ALTCHA](https://altcha.org) challenges in Go applications. It implements the ALTCHA v2 proof-of-work protocol based on key derivation functions (KDF).

## Compatibility

- Go 1.22+

## Installation

```sh
go get github.com/altcha-org/altcha-lib-go
```

## Packages

| Package | Import path | Description |
|---|---|---|
| v2 (default) | `github.com/altcha-org/altcha-lib-go` | ALTCHA v2 PoW protocol |
| v1 | `github.com/altcha-org/altcha-lib-go/v1` | Legacy ALTCHA v1 protocol |

## Usage

### Create a challenge

```go
import altcha "github.com/altcha-org/altcha-lib-go"

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

### HTTP server example

See [`examples/server`](./examples/server) for a minimal HTTP server with `GET /challenge` and `POST /submit` endpoints.

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
| `KeyPrefix` | `string` | Expected key prefix the solver must match |
| `KeyPrefixLength` | `int` | Random prefix length when `Counter` is not set (default: `KeyLength/2`) |
| `Counter` | `*int` | Deterministic counter; when set, derives the key prefix from this counter |
| `MemoryCost` | `int` | Memory cost (Scrypt r / Argon2id KiB) |
| `Parallelism` | `int` | Parallelism (Scrypt p / Argon2id threads) |
| `ExpiresAt` | `*time.Time` | Optional challenge expiry |
| `Data` | `map[string]interface{}` | Optional arbitrary data embedded in the challenge |

### `SolveChallenge(options SolveChallengeOptions) (*Solution, error)`

Brute-forces counter values until the derived key matches the challenge prefix. Returns `nil` if stopped via `StopChan`.

| Field | Type | Description |
|---|---|---|
| `Challenge` | `Challenge` | The challenge to solve |
| `DeriveKey` | `DeriveKeyFunc` | Key derivation function (must match the one used to create the challenge) |
| `CounterStart` | `int` | Starting counter value (default: 0) |
| `CounterStep` | `int` | Counter increment per iteration (default: 1) |
| `StopChan` | `<-chan struct{}` | Optional channel to abort solving |

### `VerifySolution(options VerifySolutionOptions) (VerifySolutionResult, error)`

Verifies a submitted solution against a challenge.

| Field | Type | Description |
|---|---|---|
| `Challenge` | `Challenge` | The original challenge |
| `Solution` | `Solution` | The submitted solution |
| `DeriveKey` | `DeriveKeyFunc` | Key derivation function |
| `HMACSignatureSecret` | `string` | Secret used when the challenge was signed |
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

The original ALTCHA v1 protocol (SHA-based hash challenge) is available under the `v1` sub-package:

```go
import v1 "github.com/altcha-org/altcha-lib-go/v1"

challenge, err := v1.CreateChallenge(v1.ChallengeOptions{
    HMACKey:   "secret",
    MaxNumber: 100000,
})

ok, err := v1.VerifySolution(payload, "secret", true)
```

## License

MIT
