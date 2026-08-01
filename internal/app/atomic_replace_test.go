//go:build darwin || linux

package app

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

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
