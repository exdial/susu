package cryptox

import "errors"

const (
	// CurrentVersion is the crypto metadata and encrypted-file format version
	// emitted by this package.
	CurrentVersion uint32 = 1

	// MasterKeySize is the required repository master-key size in bytes.
	MasterKeySize = 32

	// AlgorithmArgon2id identifies the supported password KDF.
	AlgorithmArgon2id = "argon2id"
	// AlgorithmAES256GCM identifies the supported key-wrap and file cipher.
	AlgorithmAES256GCM = "aes-256-gcm"
)

var (
	// ErrInvalidPassword indicates that a repository could not be unlocked with
	// the supplied password. Authentication cannot distinguish a bad password
	// from a same-length modification to the wrapped master key.
	ErrInvalidPassword = errors.New("cryptox: invalid password")

	// ErrCorruptCiphertext indicates that an encrypted-file envelope is invalid
	// or failed authentication. A wrong master key or logical path also causes
	// authentication to fail with this error.
	ErrCorruptCiphertext = errors.New("cryptox: corrupt ciphertext")

	// ErrUnsupportedFormat indicates an unknown crypto version or algorithm.
	ErrUnsupportedFormat = errors.New("cryptox: unsupported crypto format")

	// ErrInvalidMetadata indicates incomplete, malformed, or unsafe repository
	// crypto metadata.
	ErrInvalidMetadata = errors.New("cryptox: invalid crypto metadata")

	// ErrInvalidMasterKey indicates that a file operation did not receive an
	// AES-256 repository master key.
	ErrInvalidMasterKey = errors.New("cryptox: invalid repository master key")

	// ErrInvalidLogicalPath indicates that a file operation received no portable
	// logical path to authenticate as associated data.
	ErrInvalidLogicalPath = errors.New("cryptox: invalid logical path")
)

// Argon2Parameters contains Argon2id work factors. Memory is measured in KiB,
// matching golang.org/x/crypto/argon2.
type Argon2Parameters struct {
	Time        uint32 `json:"time"`
	Memory      uint32 `json:"memory"`
	Parallelism uint8  `json:"parallelism"`
	KeyLength   uint32 `json:"keyLength"`
}

// KDFMetadata describes how the password-derived key-encryption key is made.
// Salt is encoded as base64 by encoding/json.
type KDFMetadata struct {
	Algorithm  string           `json:"algorithm"`
	Parameters Argon2Parameters `json:"parameters"`
	Salt       []byte           `json:"salt"`
}

// WrapMetadata contains the authenticated encryption of the repository master
// key. Nonce and Ciphertext are encoded as base64 by encoding/json.
type WrapMetadata struct {
	Algorithm  string `json:"algorithm"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Metadata is the versioned repository crypto metadata intended to be embedded
// directly in a JSON manifest.
type Metadata struct {
	Version uint32       `json:"version"`
	KDF     KDFMetadata  `json:"kdf"`
	Wrap    WrapMetadata `json:"wrap"`
}

// Envelope is the versioned serialized representation of one encrypted
// sensitive file. Encrypt and Decrypt marshal and unmarshal it as JSON.
type Envelope struct {
	Version    uint32 `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
