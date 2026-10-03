module github.com/altcha-org/altcha-lib-go/v2

go 1.25.0

require golang.org/x/crypto v0.54.0

require golang.org/x/sys v0.47.0 // indirect

// VerifySolution can accept unverified solutions (missing DeriveKey or HMACSignatureSecret).
retract [v2.0.0, v2.3.0]
