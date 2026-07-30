package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorePaths(t *testing.T) {
	temp := t.TempDir()
	home := filepath.Join(temp, "home with spaces")
	xdg := filepath.Join(temp, "state with spaces")

	tests := []struct {
		name string
		home string
		xdg  string
		want string
	}{
		{
			name: "XDG state home",
			home: home,
			xdg:  xdg,
			want: filepath.Join(xdg, "susu", "state.json"),
		},
		{
			name: "HOME fallback",
			home: home,
			want: filepath.Join(home, ".local", "state", "susu", "state.json"),
		},
		{
			name: "XDG does not require HOME",
			xdg:  xdg,
			want: filepath.Join(xdg, "susu", "state.json"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewStore(test.home, test.xdg)
			if err != nil {
				t.Fatal(err)
			}
			if store.Path() != test.want {
				t.Fatalf("Path() = %q, want %q", store.Path(), test.want)
			}
			if store.Directory() != filepath.Dir(test.want) {
				t.Fatalf("Directory() = %q, want %q", store.Directory(), filepath.Dir(test.want))
			}
		})
	}
}

func TestSaveAndLoad(t *testing.T) {
	temp := t.TempDir()
	home := filepath.Join(temp, "home")
	store := mustStore(t, home, "")
	repository := filepath.Join(temp, "repositories", "dotfiles with spaces", "..", "dotfiles with spaces")
	wantRepository, err := filepath.Abs(repository)
	if err != nil {
		t.Fatal(err)
	}
	wantRepository = filepath.Clean(wantRepository)

	if err := store.Save(repository); err != nil {
		t.Fatalf("Save(): %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if got != wantRepository {
		t.Fatalf("Load() = %q, want %q", got, wantRepository)
	}

	contents, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(contents, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded["repository"] != wantRepository {
		t.Fatalf("state JSON = %s", contents)
	}

	assertPermissions(t, filepath.Dir(store.Path()), 0o700)
	assertPermissions(t, store.Path(), 0o600)
}

func TestSaveReplacesStateAndLeavesNoTemporaryFiles(t *testing.T) {
	temp := t.TempDir()
	store := mustStore(t, filepath.Join(temp, "home"), "")
	first := filepath.Join(temp, "first")
	second := filepath.Join(temp, "second")

	if err := store.Save(first); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(second); err != nil {
		t.Fatal(err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != second {
		t.Fatalf("Load() = %q, want %q", got, second)
	}

	entries, err := os.ReadDir(filepath.Dir(store.Path()))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("state directory entries = %v, want only state.json", entryNames(entries))
	}
}

func TestSaveTightensExistingStateDirectoryPermissions(t *testing.T) {
	temp := t.TempDir()
	store := mustStore(t, filepath.Join(temp, "home"), "")
	directory := filepath.Dir(store.Path())
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := store.Save(filepath.Join(temp, "repository")); err != nil {
		t.Fatal(err)
	}
	assertPermissions(t, directory, 0o700)
}

func TestLoadNotInitialized(t *testing.T) {
	temp := t.TempDir()
	store := mustStore(t, filepath.Join(temp, "home"), "")

	_, err := store.Load()
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Load() error = %v, want ErrNotInitialized", err)
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("Load() error is not clear: %v", err)
	}
}

func TestLoadRejectsSymlinkStateFile(t *testing.T) {
	temp := t.TempDir()
	store := mustStore(t, filepath.Join(temp, "home"), "")
	outside := filepath.Join(temp, "outside-state.json")
	if err := os.WriteFile(outside, []byte(`{"repository":"/tmp/repository"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(store.Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, store.Path()); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrMalformedState) {
		t.Fatalf("Load() error = %v, want ErrMalformedState", err)
	}
}

func TestLoadRejectsMalformedState(t *testing.T) {
	temp := t.TempDir()
	absolute := filepath.Join(temp, "repository")
	tooLarge := strings.Repeat(" ", maxStateFileSize+1)

	tests := []struct {
		name     string
		contents string
	}{
		{"empty file", ""},
		{"invalid JSON", "{"},
		{"missing repository", `{}`},
		{"empty repository", `{"repository":""}`},
		{"relative repository", `{"repository":"relative/repository"}`},
		{"noncanonical repository", `{"repository":"` + filepath.ToSlash(filepath.Join(temp, "one")) + `/../two"}`},
		{"unknown field", `{"repository":"` + filepath.ToSlash(absolute) + `","extra":true}`},
		{"multiple values", `{"repository":"` + filepath.ToSlash(absolute) + `"} {}`},
		{"trailing data", `{"repository":"` + filepath.ToSlash(absolute) + `"} trailing`},
		{"too large", tooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := mustStore(t, filepath.Join(temp, test.name, "home"), "")
			writeStateForTest(t, store.Path(), test.contents)

			_, err := store.Load()
			if !errors.Is(err, ErrMalformedState) {
				t.Fatalf("Load() error = %v, want ErrMalformedState", err)
			}
			if !strings.Contains(err.Error(), "malformed local state") {
				t.Fatalf("Load() error is not clear: %v", err)
			}
		})
	}
}

func TestSaveRejectsEmptyRepository(t *testing.T) {
	store := mustStore(t, filepath.Join(t.TempDir(), "home"), "")
	if err := store.Save(""); err == nil {
		t.Fatal("Save() succeeded with an empty repository")
	}
}

func TestNewStoreRejectsRelativeRoots(t *testing.T) {
	temp := t.TempDir()
	if _, err := NewStore("relative-home", ""); err == nil {
		t.Fatal("NewStore() accepted a relative HOME")
	}
	if _, err := NewStore(temp, "relative-state"); err == nil {
		t.Fatal("NewStore() accepted a relative XDG_STATE_HOME")
	}
}

func TestNewStoreFromEnv(t *testing.T) {
	temp := t.TempDir()
	home := filepath.Join(temp, "home")
	xdg := filepath.Join(temp, "state")
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", xdg)

	store, err := NewStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(xdg, "susu", "state.json")
	if store.Path() != want {
		t.Fatalf("Path() = %q, want %q", store.Path(), want)
	}
}

func mustStore(t *testing.T, home, xdgStateHome string) *Store {
	t.Helper()
	store, err := NewStore(home, xdgStateHome)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func writeStateForTest(t *testing.T, statePath, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertPermissions(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("permissions for %q = %04o, want %04o", path, got, want)
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
