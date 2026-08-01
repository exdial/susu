//go:build darwin || linux

package safefs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRegularDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "real", "file"), []byte("contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := OpenRegular(root, filepath.Join("real", "file"))
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()

	if err := os.Symlink(filepath.Join("real", "file"), filepath.Join(root, "leaf-link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := OpenRegular(root, "leaf-link"); err == nil {
		t.Fatal("OpenRegular followed a leaf symlink")
	}
	if err := os.Symlink("real", filepath.Join(root, "parent-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRegular(root, filepath.Join("parent-link", "file")); err == nil {
		t.Fatal("OpenRegular followed a parent symlink")
	}
}

func TestStableParentDescriptorCannotBeRedirectedByPathSwap(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	directory, leaf, err := OpenParent(root, filepath.Join("parent", "file"), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	moved := filepath.Join(root, "moved-parent")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, parent); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	temporary, temporaryName, err := directory.CreateTemp(".test-", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := temporary.Write([]byte("stable")); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := directory.Rename(temporaryName, leaf); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "file")); !os.IsNotExist(err) {
		t.Fatalf("stable directory write escaped to replacement path: %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(moved, "file"))
	if err != nil || string(contents) != "stable" {
		t.Fatalf("stable parent contents = %q, error = %v", contents, err)
	}
}

func TestCreateTempExcludesDestinationNameBeforeCreation(t *testing.T) {
	root := t.TempDir()
	directory, _, err := OpenParent(root, "destination", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	const (
		excluded = ".test-000000000000000000000000.tmp"
		wantName = ".test-111111111111111111111111.tmp"
	)
	random := append(make([]byte, 12), bytes.Repeat([]byte{0x11}, 12)...)
	file, name, err := directory.createTemp(".test-", 0o600, excluded, bytes.NewReader(random))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	defer directory.Remove(name)
	if name != wantName {
		t.Fatalf("temporary name = %q, want %q", name, wantName)
	}
	if _, err := os.Lstat(filepath.Join(root, excluded)); !os.IsNotExist(err) {
		t.Fatalf("excluded destination name was created: %v", err)
	}
}

func TestStableParentCreateAndRename(t *testing.T) {
	root := t.TempDir()
	directory, leaf, err := OpenParent(root, filepath.Join("nested", "file"), true, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if leaf != "file" {
		t.Fatalf("leaf = %q", leaf)
	}
	temporary, temporaryName, err := directory.CreateTemp(".test-", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := temporary.Write([]byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := directory.Rename(temporaryName, leaf); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(root, "nested", "file"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "value" {
		t.Fatalf("contents = %q", contents)
	}
}
