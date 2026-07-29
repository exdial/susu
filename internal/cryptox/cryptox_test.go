package cryptox

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestInitializeUnlockEncryptDecryptRoundTrip(t *testing.T) {
	password := []byte("correct horse battery staple")
	defer ZeroBytes(password)

	metadata, masterKey, err := Initialize(password)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer ZeroBytes(masterKey)

	if len(masterKey) != MasterKeySize {
		t.Fatalf("Initialize() master-key length = %d, want %d", len(masterKey), MasterKeySize)
	}
	if metadata.Version != CurrentVersion {
		t.Fatalf("Initialize() metadata version = %d, want %d", metadata.Version, CurrentVersion)
	}
	if metadata.KDF.Algorithm != AlgorithmArgon2id {
		t.Fatalf("Initialize() KDF algorithm = %q, want %q", metadata.KDF.Algorithm, AlgorithmArgon2id)
	}
	if metadata.Wrap.Algorithm != AlgorithmAES256GCM {
		t.Fatalf("Initialize() wrap algorithm = %q, want %q", metadata.Wrap.Algorithm, AlgorithmAES256GCM)
	}

	serializedMetadata, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("json.Marshal(Metadata) error = %v", err)
	}
	var decodedMetadata Metadata
	if err := json.Unmarshal(serializedMetadata, &decodedMetadata); err != nil {
		t.Fatalf("json.Unmarshal(Metadata) error = %v", err)
	}

	unlockedKey, err := Unlock(password, decodedMetadata)
	if err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	defer ZeroBytes(unlockedKey)
	if !bytes.Equal(unlockedKey, masterKey) {
		t.Fatal("Unlock() returned a different repository master key")
	}

	logicalPath := "${XDG_CONFIG_HOME}/service/credentials.json"
	plaintext := []byte("secret contents\n")
	serializedEnvelope, err := Encrypt(unlockedKey, logicalPath, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	var envelope Envelope
	if err := json.Unmarshal(serializedEnvelope, &envelope); err != nil {
		t.Fatalf("Encrypt() returned invalid JSON: %v", err)
	}
	if envelope.Version != CurrentVersion {
		t.Fatalf("Encrypt() envelope version = %d, want %d", envelope.Version, CurrentVersion)
	}
	if envelope.Algorithm != AlgorithmAES256GCM {
		t.Fatalf("Encrypt() envelope algorithm = %q, want %q", envelope.Algorithm, AlgorithmAES256GCM)
	}

	decrypted, err := Decrypt(unlockedKey, logicalPath, serializedEnvelope)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	defer ZeroBytes(decrypted)
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt() plaintext = %q, want %q", decrypted, plaintext)
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	password := []byte("right password")
	metadata, masterKey, err := initializeWithParameters(password, testArgon2Parameters())
	if err != nil {
		t.Fatalf("initializeWithParameters() error = %v", err)
	}
	defer ZeroBytes(password)
	defer ZeroBytes(masterKey)

	wrongPassword := []byte("wrong password")
	defer ZeroBytes(wrongPassword)
	unlocked, err := Unlock(wrongPassword, metadata)
	if unlocked != nil {
		ZeroBytes(unlocked)
		t.Fatal("Unlock() returned a key for the wrong password")
	}
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("Unlock() error = %v, want ErrInvalidPassword", err)
	}
	if !strings.Contains(err.Error(), "password") {
		t.Fatalf("Unlock() error = %q, want actionable password context", err)
	}
}

func TestDecryptCorruptedCiphertext(t *testing.T) {
	masterKey := randomMasterKey(t)
	defer ZeroBytes(masterKey)

	serialized, err := Encrypt(masterKey, "~/.ssh/config", []byte("Host example\n"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	var envelope Envelope
	if err := json.Unmarshal(serialized, &envelope); err != nil {
		t.Fatalf("json.Unmarshal(Envelope) error = %v", err)
	}
	envelope.Ciphertext[len(envelope.Ciphertext)-1] ^= 0x01
	corrupted, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal(Envelope) error = %v", err)
	}

	plaintext, err := Decrypt(masterKey, "~/.ssh/config", corrupted)
	if plaintext != nil {
		ZeroBytes(plaintext)
		t.Fatal("Decrypt() returned plaintext for corrupted ciphertext")
	}
	if !errors.Is(err, ErrCorruptCiphertext) {
		t.Fatalf("Decrypt() error = %v, want ErrCorruptCiphertext", err)
	}
}

func TestDecryptRejectsLogicalPathMismatch(t *testing.T) {
	masterKey := randomMasterKey(t)
	defer ZeroBytes(masterKey)

	serialized, err := Encrypt(masterKey, "~/.kube/config", []byte("apiVersion: v1\n"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	plaintext, err := Decrypt(masterKey, "~/.kube/other-config", serialized)
	if plaintext != nil {
		ZeroBytes(plaintext)
		t.Fatal("Decrypt() returned plaintext for a mismatched logical path")
	}
	if !errors.Is(err, ErrCorruptCiphertext) {
		t.Fatalf("Decrypt() error = %v, want ErrCorruptCiphertext", err)
	}
}

func TestDecryptStrictlyRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	masterKey := randomMasterKey(t)
	defer ZeroBytes(masterKey)
	serialized, err := Encrypt(masterKey, "~/.secret", []byte("secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	withUnknownField := append([]byte(nil), bytes.TrimSuffix(serialized, []byte("}"))...)
	withUnknownField = append(withUnknownField, []byte(",\"unknown\":true}")...)
	for _, malformed := range [][]byte{withUnknownField, append(append([]byte(nil), serialized...), []byte(" {}")...)} {
		plaintext, err := Decrypt(masterKey, "~/.secret", malformed)
		if plaintext != nil {
			ZeroBytes(plaintext)
			t.Fatal("Decrypt() returned plaintext for malformed envelope JSON")
		}
		if !errors.Is(err, ErrCorruptCiphertext) {
			t.Fatalf("Decrypt() error = %v, want ErrCorruptCiphertext", err)
		}
	}
}

func TestUnsupportedVersions(t *testing.T) {
	t.Run("metadata", func(t *testing.T) {
		password := []byte("repository password")
		metadata, masterKey, err := initializeWithParameters(password, testArgon2Parameters())
		if err != nil {
			t.Fatalf("initializeWithParameters() error = %v", err)
		}
		defer ZeroBytes(password)
		defer ZeroBytes(masterKey)

		metadata.Version = CurrentVersion + 1
		unlocked, err := Unlock(password, metadata)
		if unlocked != nil {
			ZeroBytes(unlocked)
			t.Fatal("Unlock() returned a key for an unsupported metadata version")
		}
		if !errors.Is(err, ErrUnsupportedFormat) {
			t.Fatalf("Unlock() error = %v, want ErrUnsupportedFormat", err)
		}
	})

	t.Run("file envelope", func(t *testing.T) {
		masterKey := randomMasterKey(t)
		defer ZeroBytes(masterKey)

		serialized, err := Encrypt(masterKey, "~/.config/token", []byte("token"))
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}
		var envelope Envelope
		if err := json.Unmarshal(serialized, &envelope); err != nil {
			t.Fatalf("json.Unmarshal(Envelope) error = %v", err)
		}
		envelope.Version = CurrentVersion + 1
		unsupported, err := json.Marshal(envelope)
		if err != nil {
			t.Fatalf("json.Marshal(Envelope) error = %v", err)
		}

		plaintext, err := Decrypt(masterKey, "~/.config/token", unsupported)
		if plaintext != nil {
			ZeroBytes(plaintext)
			t.Fatal("Decrypt() returned plaintext for an unsupported envelope version")
		}
		if !errors.Is(err, ErrUnsupportedFormat) {
			t.Fatalf("Decrypt() error = %v, want ErrUnsupportedFormat", err)
		}
	})
}

func TestEncryptUsesIndependentNonces(t *testing.T) {
	masterKey := randomMasterKey(t)
	defer ZeroBytes(masterKey)

	firstJSON, err := Encrypt(masterKey, "~/.netrc", []byte("same plaintext"))
	if err != nil {
		t.Fatalf("first Encrypt() error = %v", err)
	}
	secondJSON, err := Encrypt(masterKey, "~/.netrc", []byte("same plaintext"))
	if err != nil {
		t.Fatalf("second Encrypt() error = %v", err)
	}

	var first, second Envelope
	if err := json.Unmarshal(firstJSON, &first); err != nil {
		t.Fatalf("json.Unmarshal(first Envelope) error = %v", err)
	}
	if err := json.Unmarshal(secondJSON, &second); err != nil {
		t.Fatalf("json.Unmarshal(second Envelope) error = %v", err)
	}
	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("Encrypt() reused a file nonce")
	}
}

func TestDefaultArgon2ParametersAreProductionSafe(t *testing.T) {
	parameters := DefaultArgon2Parameters()
	if parameters.Time < 3 {
		t.Fatalf("default Argon2id time = %d, want at least 3", parameters.Time)
	}
	if parameters.Memory < 64*1024 {
		t.Fatalf("default Argon2id memory = %d KiB, want at least 65536 KiB", parameters.Memory)
	}
	if parameters.Parallelism == 0 {
		t.Fatal("default Argon2id parallelism must not be zero")
	}
	if parameters.KeyLength != MasterKeySize {
		t.Fatalf("default Argon2id key length = %d, want %d", parameters.KeyLength, MasterKeySize)
	}
}

func TestZeroBytes(t *testing.T) {
	secret := []byte("erase me")
	ZeroBytes(secret)
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatalf("ZeroBytes() left non-zero data: %v", secret)
	}
}

func testArgon2Parameters() Argon2Parameters {
	return Argon2Parameters{
		Time:        1,
		Memory:      8 * 1024,
		Parallelism: 1,
		KeyLength:   MasterKeySize,
	}
}

func randomMasterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read(master key) error = %v", err)
	}
	return key
}
