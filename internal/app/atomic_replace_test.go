//go:build darwin || linux

package app

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"susu/internal/safefs"
)

const (
	broadStagingSentinelName      = ".susu-apply-user-backup.tmp"
	exactShapeStagingSentinelName = ".susu-apply-0123456789abcdef01234567.tmp"
)

func TestAtomicReplacePreRenameFailuresPreserveDestinationAndCleanOnlyOwnedTemporary(t *testing.T) {
	tests := []struct {
		name       string
		writeFault func(io.Writer, []byte, error) error
		hooks      func(error) atomicReplaceHooks
	}{
		{
			name: "write",
			writeFault: func(_ io.Writer, _ []byte, injected error) error {
				return injected
			},
		},
		{
			name: "partial write",
			writeFault: func(writer io.Writer, replacement []byte, injected error) error {
				partial := replacement[:len(replacement)/2]
				written, err := writer.Write(partial)
				if err != nil {
					return err
				}
				if written != len(partial) {
					return io.ErrShortWrite
				}
				return injected
			},
		},
		{
			name: "file sync",
			hooks: func(injected error) atomicReplaceHooks {
				return atomicReplaceHooks{syncFile: func(_ *os.File) error { return injected }}
			},
		},
		{
			name: "explicit close",
			hooks: func(injected error) atomicReplaceHooks {
				return atomicReplaceHooks{closeFile: func(_ *os.File) error { return injected }}
			},
		},
		{
			name: "rename",
			hooks: func(injected error) atomicReplaceHooks {
				return atomicReplaceHooks{rename: func(_ *safefs.Directory, _, _ string) error { return injected }}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			destination := filepath.Join(root, "managed")
			oldDestination := []byte("old destination contents\n")
			replacement := []byte("replacement contents\n")
			mustWriteTestFile(t, destination, oldDestination, 0o644)
			sentinels := writeAtomicReplaceStagingSentinels(t, root)

			injected := errors.New("injected " + test.name + " failure")
			hooks := atomicReplaceHooks{}
			if test.hooks != nil {
				hooks = test.hooks(injected)
			}
			var temporaryName string
			write := func(writer io.Writer) error {
				temporaryName = testAtomicReplaceStagingName(t, writer)
				if test.writeFault != nil {
					return test.writeFault(writer, replacement, injected)
				}
				return writeAll(writer, replacement)
			}

			committed, err := atomicReplaceRootedWithHooks(root, "managed", 0o644, 0o755, write, hooks)
			if committed {
				t.Fatal("atomicReplaceRootedWithHooks() committed = true, want false")
			}
			if !errors.Is(err, injected) {
				t.Fatalf("atomicReplaceRootedWithHooks() error = %v, want injected error %v", err, injected)
			}
			assertTestFileContents(t, destination, oldDestination)
			if temporaryName == "" {
				t.Fatal("atomicReplaceRootedWithHooks() did not expose its owned temporary name to the writer")
			}
			if _, statErr := os.Lstat(filepath.Join(root, temporaryName)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("owned temporary %q stat error = %v, want not exist", temporaryName, statErr)
			}
			assertAtomicReplaceStagingSentinels(t, root, sentinels)
			assertTestDirectoryNames(t, root, "managed", broadStagingSentinelName, exactShapeStagingSentinelName)
		})
	}
}

func TestAtomicReplaceCleanupRemovalFailurePreservesPrimaryErrorAndOwnedResidue(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "managed")
	oldDestination := []byte("old destination contents\n")
	replacement := []byte("replacement contents\n")
	residue := replacement[:len(replacement)/2]
	mustWriteTestFile(t, destination, oldDestination, 0o644)
	sentinels := writeAtomicReplaceStagingSentinels(t, root)

	primaryError := errors.New("injected primary write failure")
	cleanupError := errors.New("injected temporary removal failure")
	var temporaryName string
	var removalName string
	committed, err := atomicReplaceRootedWithHooks(
		root,
		"managed",
		0o644,
		0o755,
		func(writer io.Writer) error {
			temporaryName = testAtomicReplaceStagingName(t, writer)
			if err := writeAll(writer, residue); err != nil {
				return err
			}
			return primaryError
		},
		atomicReplaceHooks{removeTemporary: func(_ *safefs.Directory, name string) error {
			removalName = name
			return cleanupError
		}},
	)
	if committed {
		t.Fatal("atomicReplaceRootedWithHooks() committed = true, want false")
	}
	if !errors.Is(err, primaryError) {
		t.Fatalf("atomicReplaceRootedWithHooks() error = %v, want primary error %v", err, primaryError)
	}
	if errors.Is(err, cleanupError) {
		t.Fatalf("atomicReplaceRootedWithHooks() error = %v, cleanup error must not replace or join the primary error", err)
	}
	if removalName != temporaryName {
		t.Fatalf("temporary removal name = %q, want exact owned name %q", removalName, temporaryName)
	}
	assertTestFileContents(t, destination, oldDestination)
	assertTestFileContents(t, filepath.Join(root, temporaryName), residue)
	assertAtomicReplaceStagingSentinels(t, root, sentinels)
	assertTestDirectoryNames(t, root, "managed", temporaryName, broadStagingSentinelName, exactShapeStagingSentinelName)
}

func TestAtomicReplacePreservesReusedStagingNameAfterRename(t *testing.T) {
	root := t.TempDir()
	replacement := []byte("managed contents\n")
	unmanaged := []byte("unmanaged contents\n")
	var reusedPath string

	committed, err := atomicReplaceRootedWithHooks(
		root,
		"managed",
		0o644,
		0o755,
		func(writer io.Writer) error { return writeAll(writer, replacement) },
		atomicReplaceHooks{afterRename: func(temporaryName string) error {
			reusedPath = filepath.Join(root, temporaryName)
			return os.WriteFile(reusedPath, unmanaged, 0o600)
		}},
	)
	if err != nil {
		t.Fatalf("atomicReplaceRootedWithHooks() error = %v", err)
	}
	if !committed {
		t.Fatal("atomicReplaceRootedWithHooks() committed = false, want true")
	}
	assertTestFileContents(t, filepath.Join(root, "managed"), replacement)
	assertTestFileContents(t, reusedPath, unmanaged)
}

func TestAtomicReplaceDirectorySyncFailureReportsCommittedReplacement(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "managed")
	oldDestination := []byte("old destination contents\n")
	replacement := []byte("replacement contents\n")
	unmanaged := []byte("reused staging name contents\n")
	mustWriteTestFile(t, destination, oldDestination, 0o644)

	injected := errors.New("injected directory sync failure")
	var reusedPath string
	committed, err := atomicReplaceRootedWithHooks(
		root,
		"managed",
		0o644,
		0o755,
		func(writer io.Writer) error { return writeAll(writer, replacement) },
		atomicReplaceHooks{
			afterRename: func(temporaryName string) error {
				reusedPath = filepath.Join(root, temporaryName)
				return os.WriteFile(reusedPath, unmanaged, 0o600)
			},
			syncDirectory: func(_ *safefs.Directory) error { return injected },
		},
	)
	if !committed {
		t.Fatal("atomicReplaceRootedWithHooks() committed = false, want true")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("atomicReplaceRootedWithHooks() error = %v, want injected error %v", err, injected)
	}
	if !strings.Contains(err.Error(), "destination was replaced but directory sync failed") {
		t.Fatalf("atomicReplaceRootedWithHooks() error = %q, want committed replacement and uncertain durability context", err)
	}
	assertTestFileContents(t, destination, replacement)
	assertTestFileContents(t, reusedPath, unmanaged)
	assertTestDirectoryNames(t, root, "managed", filepath.Base(reusedPath))
}

func writeAtomicReplaceStagingSentinels(t *testing.T, root string) map[string][]byte {
	t.Helper()
	sentinels := map[string][]byte{
		broadStagingSentinelName:      []byte("broad staging sentinel contents\n"),
		exactShapeStagingSentinelName: []byte("exact-shape staging sentinel contents\n"),
	}
	for name, contents := range sentinels {
		mustWriteTestFile(t, filepath.Join(root, name), contents, 0o600)
	}
	return sentinels
}

func assertAtomicReplaceStagingSentinels(t *testing.T, root string, sentinels map[string][]byte) {
	t.Helper()
	for name, contents := range sentinels {
		assertTestFileContents(t, filepath.Join(root, name), contents)
	}
}

func testAtomicReplaceStagingName(t *testing.T, writer io.Writer) string {
	t.Helper()
	file, ok := writer.(*os.File)
	if !ok {
		t.Fatalf("atomic replacement writer type = %T, want *os.File", writer)
	}
	return filepath.Base(file.Name())
}

func mustWriteTestFile(t *testing.T, filename string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filename, contents, mode); err != nil {
		t.Fatalf("write %q: %v", filename, err)
	}
}

func assertTestFileContents(t *testing.T, filename string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %q: %v", filename, err)
	}
	if string(got) != string(want) {
		t.Fatalf("contents of %q = %q, want %q", filename, got, want)
	}
}

func assertTestDirectoryNames(t *testing.T, directory string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read directory %q: %v", directory, err)
	}
	if len(entries) != len(want) {
		t.Fatalf("directory %q has %d entries, want %d: %v", directory, len(entries), len(want), want)
	}
	remaining := make(map[string]struct{}, len(want))
	for _, name := range want {
		remaining[name] = struct{}{}
	}
	for _, entry := range entries {
		if _, ok := remaining[entry.Name()]; !ok {
			t.Fatalf("directory %q contains unexpected entry %q; want %v", directory, entry.Name(), want)
		}
		delete(remaining, entry.Name())
	}
	if len(remaining) != 0 {
		t.Fatalf("directory %q is missing entries %v", directory, remaining)
	}
}
