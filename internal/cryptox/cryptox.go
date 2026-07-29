package cryptox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize        = 16
	gcmNonceSize    = 12
	gcmTagSize      = 16
	maxArgon2Time   = 10
	maxArgon2Memory = 256 * 1024 // KiB (256 MiB)
	maxParallelism  = 16

	wrapAADV1       = "susu:repository-master-key:v1"
	fileAADPrefixV1 = "susu:sensitive-file:v1\x00"
)

// DefaultArgon2Parameters returns the production defaults used by Initialize.
// They match RFC 9106's memory-constrained Argon2id recommendation: 64 MiB of
// memory, three passes, and four lanes, producing a 256-bit KEK.
func DefaultArgon2Parameters() Argon2Parameters {
	return Argon2Parameters{
		Time:        3,
		Memory:      64 * 1024,
		Parallelism: 4,
		KeyLength:   MasterKeySize,
	}
}

// Initialize creates a random repository master key and wraps it with an
// AES-256-GCM KEK derived from password using Argon2id. The returned Metadata
// can be embedded directly in the repository manifest. The caller must keep the
// returned master key in memory only and should call ZeroBytes when done.
func Initialize(password []byte) (Metadata, []byte, error) {
	return initializeWithParameters(password, DefaultArgon2Parameters())
}

// initializeWithParameters exists so package tests can use inexpensive work
// factors. Production callers always enter through Initialize and its defaults.
func initializeWithParameters(password []byte, parameters Argon2Parameters) (Metadata, []byte, error) {
	if len(password) == 0 {
		return Metadata{}, nil, fmt.Errorf("%w: password must not be empty", ErrInvalidPassword)
	}
	if err := validateArgon2Parameters(parameters); err != nil {
		return Metadata{}, nil, err
	}

	masterKey := make([]byte, MasterKeySize)
	if _, err := rand.Read(masterKey); err != nil {
		return Metadata{}, nil, fmt.Errorf("cryptox: generate repository master key: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		ZeroBytes(masterKey)
		return Metadata{}, nil, fmt.Errorf("cryptox: generate Argon2id salt: %w", err)
	}

	kek := deriveKEK(password, salt, parameters)
	defer ZeroBytes(kek)

	aead, err := newAES256GCM(kek)
	if err != nil {
		ZeroBytes(masterKey)
		return Metadata{}, nil, fmt.Errorf("cryptox: initialize master-key wrapper: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		ZeroBytes(masterKey)
		return Metadata{}, nil, fmt.Errorf("cryptox: generate master-key nonce: %w", err)
	}

	wrappedKey := aead.Seal(nil, nonce, masterKey, []byte(wrapAADV1))
	metadata := Metadata{
		Version: CurrentVersion,
		KDF: KDFMetadata{
			Algorithm:  AlgorithmArgon2id,
			Parameters: parameters,
			Salt:       salt,
		},
		Wrap: WrapMetadata{
			Algorithm:  AlgorithmAES256GCM,
			Nonce:      nonce,
			Ciphertext: wrappedKey,
		},
	}

	return metadata, masterKey, nil
}

// ValidateMetadata checks crypto metadata without deriving a key. It rejects
// unsupported versions and algorithms, malformed fields, and unsafe KDF work
// factors before untrusted repository data can reach Argon2id.
func ValidateMetadata(metadata Metadata) error {
	return validateMetadata(metadata)
}

// Unlock derives the repository KEK from password and authenticates and
// decrypts the wrapped master key in metadata. If authentication fails, the
// error wraps ErrInvalidPassword; cryptography cannot tell a wrong password
// from a modification to the wrapped key.
func Unlock(password []byte, metadata Metadata) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("%w: password must not be empty", ErrInvalidPassword)
	}
	if err := validateMetadata(metadata); err != nil {
		return nil, err
	}

	kek := deriveKEK(password, metadata.KDF.Salt, metadata.KDF.Parameters)
	defer ZeroBytes(kek)

	aead, err := newAES256GCM(kek)
	if err != nil {
		return nil, fmt.Errorf("cryptox: initialize master-key wrapper: %w", err)
	}

	masterKey, err := aead.Open(
		nil,
		metadata.Wrap.Nonce,
		metadata.Wrap.Ciphertext,
		[]byte(wrapAADV1),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: password is incorrect or wrapped master-key metadata was modified",
			ErrInvalidPassword,
		)
	}
	if len(masterKey) != MasterKeySize {
		ZeroBytes(masterKey)
		return nil, fmt.Errorf("%w: wrapped key decrypted to %d bytes, want %d", ErrInvalidMetadata, len(masterKey), MasterKeySize)
	}

	return masterKey, nil
}

// Encrypt encrypts plaintext with the repository master key and returns a
// versioned JSON Envelope. A fresh random nonce is generated for every call.
// logicalPath is authenticated, but not stored, and must be the exact portable
// logical path supplied later to Decrypt.
func Encrypt(masterKey []byte, logicalPath string, plaintext []byte) ([]byte, error) {
	if logicalPath == "" {
		return nil, fmt.Errorf("%w: path must not be empty", ErrInvalidLogicalPath)
	}

	aead, err := newAES256GCM(masterKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cryptox: generate file nonce: %w", err)
	}

	envelope := Envelope{
		Version:    CurrentVersion,
		Algorithm:  AlgorithmAES256GCM,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, fileAAD(logicalPath)),
	}
	serialized, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("cryptox: serialize encrypted-file envelope: %w", err)
	}

	return serialized, nil
}

// Decrypt parses and authenticates a JSON Envelope using the repository master
// key and exact portable logical path used by Encrypt. Authentication failures,
// including path/AAD mismatches, wrap ErrCorruptCiphertext.
func Decrypt(masterKey []byte, logicalPath string, serializedEnvelope []byte) ([]byte, error) {
	if logicalPath == "" {
		return nil, fmt.Errorf("%w: path must not be empty", ErrInvalidLogicalPath)
	}
	if len(masterKey) != MasterKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidMasterKey, len(masterKey), MasterKeySize)
	}
	if len(serializedEnvelope) == 0 {
		return nil, fmt.Errorf("%w: encrypted-file envelope is empty", ErrCorruptCiphertext)
	}

	decoder := json.NewDecoder(bytes.NewReader(serializedEnvelope))
	decoder.DisallowUnknownFields()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("%w: invalid envelope JSON: %v", ErrCorruptCiphertext, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: encrypted-file envelope contains multiple JSON values", ErrCorruptCiphertext)
		}
		return nil, fmt.Errorf("%w: trailing encrypted-file data: %v", ErrCorruptCiphertext, err)
	}
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}

	aead, err := newAES256GCM(masterKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, fileAAD(logicalPath))
	if err != nil {
		return nil, fmt.Errorf(
			"%w: authentication failed; ciphertext, master key, or logical path does not match",
			ErrCorruptCiphertext,
		)
	}

	return plaintext, nil
}

// ZeroBytes overwrites b in place as a best effort. Go cannot guarantee that
// compilers, runtimes, or copied buffers leave no other representation behind.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func deriveKEK(password, salt []byte, parameters Argon2Parameters) []byte {
	return argon2.IDKey(
		password,
		salt,
		parameters.Time,
		parameters.Memory,
		parameters.Parallelism,
		parameters.KeyLength,
	)
}

func newAES256GCM(key []byte) (cipher.AEAD, error) {
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidMasterKey, len(key), MasterKeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptox: initialize AES-256: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptox: initialize AES-256-GCM: %w", err)
	}
	return aead, nil
}

func validateMetadata(metadata Metadata) error {
	if metadata.Version == 0 {
		return fmt.Errorf("%w: metadata version is missing", ErrInvalidMetadata)
	}
	if metadata.Version != CurrentVersion {
		return fmt.Errorf(
			"%w: metadata version %d (supported version is %d)",
			ErrUnsupportedFormat,
			metadata.Version,
			CurrentVersion,
		)
	}
	if metadata.KDF.Algorithm == "" {
		return fmt.Errorf("%w: KDF algorithm is missing", ErrInvalidMetadata)
	}
	if metadata.KDF.Algorithm != AlgorithmArgon2id {
		return fmt.Errorf("%w: KDF algorithm %q", ErrUnsupportedFormat, metadata.KDF.Algorithm)
	}
	if err := validateArgon2Parameters(metadata.KDF.Parameters); err != nil {
		return err
	}
	if len(metadata.KDF.Salt) != saltSize {
		return fmt.Errorf("%w: Argon2id salt is %d bytes, want %d", ErrInvalidMetadata, len(metadata.KDF.Salt), saltSize)
	}
	if metadata.Wrap.Algorithm == "" {
		return fmt.Errorf("%w: key-wrap algorithm is missing", ErrInvalidMetadata)
	}
	if metadata.Wrap.Algorithm != AlgorithmAES256GCM {
		return fmt.Errorf("%w: key-wrap algorithm %q", ErrUnsupportedFormat, metadata.Wrap.Algorithm)
	}
	if len(metadata.Wrap.Nonce) != gcmNonceSize {
		return fmt.Errorf("%w: key-wrap nonce is %d bytes, want %d", ErrInvalidMetadata, len(metadata.Wrap.Nonce), gcmNonceSize)
	}
	if len(metadata.Wrap.Ciphertext) != MasterKeySize+gcmTagSize {
		return fmt.Errorf(
			"%w: wrapped master key is %d bytes, want %d",
			ErrInvalidMetadata,
			len(metadata.Wrap.Ciphertext),
			MasterKeySize+gcmTagSize,
		)
	}
	return nil
}

func validateArgon2Parameters(parameters Argon2Parameters) error {
	if parameters.Time == 0 {
		return fmt.Errorf("%w: Argon2id time must be at least 1", ErrInvalidMetadata)
	}
	if parameters.Time > maxArgon2Time {
		return fmt.Errorf("%w: Argon2id time %d exceeds safety limit %d", ErrInvalidMetadata, parameters.Time, maxArgon2Time)
	}
	if parameters.Parallelism == 0 {
		return fmt.Errorf("%w: Argon2id parallelism must be at least 1", ErrInvalidMetadata)
	}
	if parameters.Parallelism > maxParallelism {
		return fmt.Errorf(
			"%w: Argon2id parallelism %d exceeds safety limit %d",
			ErrInvalidMetadata,
			parameters.Parallelism,
			maxParallelism,
		)
	}
	minimumMemory := 8 * uint32(parameters.Parallelism)
	if parameters.Memory < minimumMemory {
		return fmt.Errorf(
			"%w: Argon2id memory must be at least %d KiB for parallelism %d",
			ErrInvalidMetadata,
			minimumMemory,
			parameters.Parallelism,
		)
	}
	if parameters.Memory > maxArgon2Memory {
		return fmt.Errorf(
			"%w: Argon2id memory %d KiB exceeds safety limit %d KiB",
			ErrInvalidMetadata,
			parameters.Memory,
			maxArgon2Memory,
		)
	}
	if parameters.KeyLength != MasterKeySize {
		return fmt.Errorf(
			"%w: Argon2id key length is %d bytes, want %d",
			ErrInvalidMetadata,
			parameters.KeyLength,
			MasterKeySize,
		)
	}
	return nil
}

func validateEnvelope(envelope Envelope) error {
	if envelope.Version == 0 {
		return fmt.Errorf("%w: envelope version is missing", ErrCorruptCiphertext)
	}
	if envelope.Version != CurrentVersion {
		return fmt.Errorf(
			"%w: encrypted-file version %d (supported version is %d)",
			ErrUnsupportedFormat,
			envelope.Version,
			CurrentVersion,
		)
	}
	if envelope.Algorithm == "" {
		return fmt.Errorf("%w: envelope algorithm is missing", ErrCorruptCiphertext)
	}
	if envelope.Algorithm != AlgorithmAES256GCM {
		return fmt.Errorf("%w: encrypted-file algorithm %q", ErrUnsupportedFormat, envelope.Algorithm)
	}
	if len(envelope.Nonce) != gcmNonceSize {
		return fmt.Errorf("%w: file nonce is %d bytes, want %d", ErrCorruptCiphertext, len(envelope.Nonce), gcmNonceSize)
	}
	if len(envelope.Ciphertext) < gcmTagSize {
		return fmt.Errorf("%w: ciphertext is too short", ErrCorruptCiphertext)
	}
	return nil
}

func fileAAD(logicalPath string) []byte {
	aad := make([]byte, len(fileAADPrefixV1)+len(logicalPath))
	copy(aad, fileAADPrefixV1)
	copy(aad[len(fileAADPrefixV1):], logicalPath)
	return aad
}
