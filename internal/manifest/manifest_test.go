package manifest

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"susu/internal/cryptox"
)

func TestEmptyAndNewManifestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		value Manifest
	}{
		{name: "new", value: New()},
		{name: "nil entries", value: Manifest{Version: CurrentVersion}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), Filename)
			if err := Save(filename, test.value); err != nil {
				t.Fatalf("Save() error = %v", err)
			}
			got, err := Load(filename)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			want := test.value
			if want.Entries == nil {
				want.Entries = []Entry{}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Load() = %#v, want %#v", got, want)
			}
			if got.Entries == nil {
				t.Fatal("Load() returned nil entries for an empty manifest")
			}

			contents, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(contents, []byte(`"entries": []`)) {
				t.Fatalf("saved empty manifest does not encode an entries array: %s", contents)
			}
			if !bytes.HasSuffix(contents, []byte("\n")) {
				t.Fatalf("saved manifest lacks a trailing newline: %q", contents)
			}
		})
	}
}

func TestLoadStrictlyRejectsInvalidJSON(t *testing.T) {
	version := strconv.Itoa(CurrentVersion)
	valid := `{"version":` + version + `,"entries":[]}`
	tests := []struct {
		name     string
		contents string
	}{
		{name: "empty", contents: ""},
		{name: "malformed JSON", contents: "{"},
		{name: "unknown top-level field", contents: `{"version":` + version + `,"entries":[],"unexpected":true}`},
		{name: "unknown entry field", contents: `{"version":` + version + `,"entries":[{"path":"~/.zshrc","source":"public/.zshrc","unexpected":true}]}`},
		{name: "trailing JSON value", contents: valid + ` {}`},
		{name: "trailing non-JSON data", contents: valid + ` trailing`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), Filename)
			if err := os.WriteFile(filename, []byte(test.contents), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := Load(filename)
			if !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Load() error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestLoadRejectsUnsupportedVersion(t *testing.T) {
	filename := filepath.Join(t.TempDir(), Filename)
	contents := `{"version":` + strconv.Itoa(CurrentVersion+1) + `,"entries":[]}`
	if err := os.WriteFile(filename, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(filename)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("Load() error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestValidateRejectsDuplicatePathsAndSources(t *testing.T) {
	tests := []struct {
		name        string
		entries     []Entry
		wantMessage string
	}{
		{
			name: "duplicate paths",
			entries: []Entry{
				{Path: "~/.zshrc", Source: "public/.zshrc"},
				{Path: "~/.zshrc", Source: "public/.zshrc"},
			},
			wantMessage: "duplicate managed path",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := New()
			value.Entries = test.entries
			err := Validate(value)
			if !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidManifest", err)
			}
			if !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("Validate() error = %q, want %q context", err, test.wantMessage)
			}
		})
	}
}

func TestValidateRejectsUnsupportedPlatforms(t *testing.T) {
	for _, platform := range []string{"windows", "freebsd", ""} {
		t.Run(platform, func(t *testing.T) {
			value := New()
			value.Entries = []Entry{{
				Path:             "~/tool/config",
				Source:           "public/tool/config",
				ExcludePlatforms: []string{platform},
			}}

			err := Validate(value)
			if !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidManifest", err)
			}
			if !strings.Contains(err.Error(), "unsupported platform") {
				t.Fatalf("Validate() error = %q, want unsupported-platform context", err)
			}
		})
	}
}

func TestValidateRejectsSensitiveEntryWithoutCrypto(t *testing.T) {
	value := New()
	value.Entries = []Entry{{
		Path:      "~/.netrc",
		Source:    "encrypted/.netrc.enc",
		Sensitive: true,
	}}

	err := Validate(value)
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("Validate() error = %v, want ErrInvalidManifest", err)
	}
	if !strings.Contains(err.Error(), "no repository crypto metadata") {
		t.Fatalf("Validate() error = %q, want missing-crypto context", err)
	}
}

func TestSourceForDeterministicHomeAndXDGMapping(t *testing.T) {
	tests := []struct {
		name      string
		logical   string
		sensitive bool
		want      string
	}{
		{name: "HOME public", logical: "~/.zshrc", want: "public/.zshrc"},
		{name: "XDG public", logical: "${XDG_CONFIG_HOME}/nvim/init.lua", want: "public/.config/nvim/init.lua"},
		{name: "HOME sensitive", logical: "~/.ssh/config", sensitive: true, want: "encrypted/.ssh/config.enc"},
		{name: "XDG sensitive", logical: "${XDG_CONFIG_HOME}/service/token", sensitive: true, want: "encrypted/.config/service/token.enc"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := SourceFor(test.logical, test.sensitive)
			if err != nil {
				t.Fatalf("SourceFor(%q, %t) error = %v", test.logical, test.sensitive, err)
			}
			if got != test.want {
				t.Fatalf("SourceFor(%q, %t) = %q, want %q", test.logical, test.sensitive, got, test.want)
			}
			again, err := SourceFor(test.logical, test.sensitive)
			if err != nil {
				t.Fatalf("second SourceFor(%q, %t) error = %v", test.logical, test.sensitive, err)
			}
			if again != got {
				t.Fatalf("SourceFor(%q, %t) was nondeterministic: %q then %q", test.logical, test.sensitive, got, again)
			}
		})
	}
}

func TestValidateRejectsNondeterministicSource(t *testing.T) {
	value := New()
	value.Entries = []Entry{{
		Path:   "${XDG_CONFIG_HOME}/nvim/init.lua",
		Source: "public/nvim/init.lua",
	}}

	err := Validate(value)
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("Validate() error = %v, want ErrInvalidManifest", err)
	}
	if !strings.Contains(err.Error(), "does not match deterministic source") {
		t.Fatalf("Validate() error = %q, want deterministic-source context", err)
	}
}

func TestValidateRejectsFileAndDescendantConflicts(t *testing.T) {
	value := New()
	value.Entries = []Entry{
		{Path: "~/tool", Source: "public/tool"},
		{Path: "~/tool/config", Source: "public/tool/config"},
	}
	if err := Validate(value); !errors.Is(err, ErrInvalidManifest) || !strings.Contains(err.Error(), "conflicts with descendant") {
		t.Fatalf("Validate() error = %v, want ancestor conflict", err)
	}
}

func TestSourceForRejectsNonportableLogicalPaths(t *testing.T) {
	invalidUTF8 := string([]byte{'~', '/', 0xff})
	for _, logical := range []string{"~/.config/tool/config", "~/line\nbreak", invalidUTF8} {
		if _, err := SourceFor(logical, false); err == nil {
			t.Fatalf("SourceFor(%q) accepted a nonportable logical path", logical)
		}
	}
}

func TestSaveAtomicallyReplacesAndSortsEntries(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, Filename)
	original := New()
	original.Entries = []Entry{{Path: "~/original", Source: "public/original"}}
	if err := Save(filename, original); err != nil {
		t.Fatalf("initial Save() error = %v", err)
	}
	originalContents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	invalid := New()
	invalid.Version = CurrentVersion + 1
	if err := Save(filename, invalid); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("Save(invalid manifest) error = %v, want ErrUnsupportedVersion", err)
	}
	contentsAfterFailure, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contentsAfterFailure, originalContents) {
		t.Fatalf("failed Save() changed the existing manifest:\nbefore: %s\nafter: %s", originalContents, contentsAfterFailure)
	}

	openOriginal, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer openOriginal.Close()

	replacement := Manifest{
		Version: CurrentVersion,
		Crypto:  mustCryptoMetadata(t),
		Entries: []Entry{
			{Path: "~/zeta", Source: "public/zeta"},
			{Path: "~/alpha", Source: "encrypted/alpha.enc", Sensitive: true},
			{Path: "~/middle", Source: "public/middle", ExcludePlatforms: []string{"darwin", "linux"}},
		},
	}
	if err := Save(filename, replacement); err != nil {
		t.Fatalf("replacement Save() error = %v", err)
	}

	contentsThroughOriginalDescriptor, err := io.ReadAll(openOriginal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contentsThroughOriginalDescriptor, originalContents) {
		t.Fatalf("Save() modified the original file instead of atomically replacing it:\nwant: %s\ngot: %s", originalContents, contentsThroughOriginalDescriptor)
	}
	currentContents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(currentContents, originalContents) {
		t.Fatal("replacement Save() left the old manifest at its path")
	}

	loaded, err := Load(filename)
	if err != nil {
		t.Fatalf("Load(replacement) error = %v", err)
	}
	gotPaths := make([]string, len(loaded.Entries))
	for index, entry := range loaded.Entries {
		gotPaths[index] = entry.Path
	}
	wantPaths := []string{"~/alpha", "~/middle", "~/zeta"}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("saved entry order = %v, want %v", gotPaths, wantPaths)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != Filename {
		t.Fatalf("manifest directory entries = %v, want only %s", directoryEntryNames(entries), Filename)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("saved manifest permissions = %04o, want 0644", got)
	}
}

func mustCryptoMetadata(t *testing.T) *cryptox.Metadata {
	t.Helper()
	password := []byte("manifest test password")
	defer cryptox.ZeroBytes(password)

	metadata, masterKey, err := cryptox.Initialize(password)
	if masterKey != nil {
		defer cryptox.ZeroBytes(masterKey)
	}
	if err != nil {
		t.Fatalf("cryptox.Initialize() error = %v", err)
	}
	return &metadata
}

func directoryEntryNames(entries []os.DirEntry) []string {
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names
}
