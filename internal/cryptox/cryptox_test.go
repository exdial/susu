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

func TestUnlockRejectsUnsupportedMetadataAlgorithms(t *testing.T) {
	password := []byte("repository password")
	defer ZeroBytes(password)

	tests := []struct {
		name   string
		mutate func(*Metadata)
	}{
		{
			name: "KDF algorithm",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Algorithm = "scrypt"
			},
		},
		{
			name: "key-wrap algorithm",
			mutate: func(metadata *Metadata) {
				metadata.Wrap.Algorithm = "chacha20-poly1305"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := validShapedCheapMetadata(t)
			test.mutate(&metadata)

			assertUnlockRejectsMetadata(t, password, metadata, ErrUnsupportedFormat)
		})
	}
}

func TestUnlockRejectsMalformedMetadataLengths(t *testing.T) {
	password := []byte("repository password")
	defer ZeroBytes(password)

	tests := []struct {
		name   string
		mutate func(*Metadata)
	}{
		{
			name: "15-byte salt",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Salt = make([]byte, 15)
			},
		},
		{
			name: "17-byte salt",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Salt = make([]byte, 17)
			},
		},
		{
			name: "11-byte wrapping nonce",
			mutate: func(metadata *Metadata) {
				metadata.Wrap.Nonce = make([]byte, 11)
			},
		},
		{
			name: "13-byte wrapping nonce",
			mutate: func(metadata *Metadata) {
				metadata.Wrap.Nonce = make([]byte, 13)
			},
		},
		{
			name: "47-byte wrapped key",
			mutate: func(metadata *Metadata) {
				metadata.Wrap.Ciphertext = make([]byte, 47)
			},
		},
		{
			name: "49-byte wrapped key",
			mutate: func(metadata *Metadata) {
				metadata.Wrap.Ciphertext = make([]byte, 49)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := validShapedCheapMetadata(t)
			test.mutate(&metadata)

			assertUnlockRejectsMetadata(t, password, metadata, ErrInvalidMetadata)
		})
	}
}

func TestUnlockRejectsOutOfBoundsArgon2ParametersBeforeDerivation(t *testing.T) {
	password := []byte("repository password")
	defer ZeroBytes(password)

	tests := []struct {
		name   string
		mutate func(*Metadata)
	}{
		{
			name: "time 0",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Parameters.Time = 0
			},
		},
		{
			name: "time 11",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Parameters.Time = 11
			},
		},
		{
			name: "parallelism 0",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Parameters.Parallelism = 0
			},
		},
		{
			name: "parallelism 17",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Parameters.Parallelism = 17
			},
		},
		{
			name: "memory 15 below minimum for parallelism 2",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Parameters.Parallelism = 2
				metadata.KDF.Parameters.Memory = 15
			},
		},
		{
			name: "memory 262145",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Parameters.Memory = 262145
			},
		},
		{
			name: "key length 31",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Parameters.KeyLength = 31
			},
		},
		{
			name: "key length 33",
			mutate: func(metadata *Metadata) {
				metadata.KDF.Parameters.KeyLength = 33
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := validShapedCheapMetadata(t)
			test.mutate(&metadata)

			// Unlock must reject unsafe work factors before Argon2id can allocate
			// memory; the 262145 KiB case is a regression guard for that ordering.
			assertUnlockRejectsMetadata(t, password, metadata, ErrInvalidMetadata)
		})
	}
}

func TestValidateMetadataAcceptsExactArgon2Boundaries(t *testing.T) {
	tests := []struct {
		name       string
		parameters Argon2Parameters
	}{
		{
			name: "minimum",
			parameters: Argon2Parameters{
				Time:        1,
				Memory:      8,
				Parallelism: 1,
				KeyLength:   32,
			},
		},
		{
			name: "maximum",
			parameters: Argon2Parameters{
				Time:        10,
				Memory:      262144,
				Parallelism: 16,
				KeyLength:   32,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := validShapedCheapMetadata(t)
			metadata.KDF.Parameters = test.parameters

			if err := ValidateMetadata(metadata); err != nil {
				t.Fatalf("ValidateMetadata() error = %v, want nil", err)
			}
		})
	}
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

func validShapedCheapMetadata(t *testing.T) Metadata {
	t.Helper()

	metadata := Metadata{
		Version: CurrentVersion,
		KDF: KDFMetadata{
			Algorithm: AlgorithmArgon2id,
			Parameters: Argon2Parameters{
				Time:        1,
				Memory:      8,
				Parallelism: 1,
				KeyLength:   MasterKeySize,
			},
			Salt: make([]byte, saltSize),
		},
		Wrap: WrapMetadata{
			Algorithm:  AlgorithmAES256GCM,
			Nonce:      make([]byte, gcmNonceSize),
			Ciphertext: make([]byte, MasterKeySize+gcmTagSize),
		},
	}
	if err := ValidateMetadata(metadata); err != nil {
		t.Fatalf("valid-shaped metadata fixture failed validation: %v", err)
	}
	return metadata
}

func assertUnlockRejectsMetadata(t *testing.T, password []byte, metadata Metadata, wantErr error) {
	t.Helper()

	key, err := Unlock(password, metadata)
	if key != nil {
		ZeroBytes(key)
		t.Fatal("Unlock() returned a non-nil key for rejected metadata")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("Unlock() error = %v, want %v", err, wantErr)
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
