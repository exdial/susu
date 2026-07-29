//go:build darwin || linux

// Package safefs provides descriptor-relative, no-symlink filesystem access for
// the two platforms supported by susu v0.1.
package safefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Directory is a stable open directory used for relative create/rename/remove
// operations without re-resolving parent pathnames.
type Directory struct {
	file *os.File
}

// OpenRegular opens one regular file below root without following any symlink
// component. The returned descriptor is the same object that was validated.
func OpenRegular(root, relative string) (*os.File, error) {
	directory, leaf, err := OpenParent(root, relative, false, 0)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	return directory.OpenRegular(leaf)
}

// OpenParent opens the parent of relative below root. When create is true,
// missing parent directories are created with mode. No symlink component is
// ever followed. The root path itself may be a symlink configured as HOME/XDG;
// it is resolved once before the root descriptor is opened.
func OpenParent(root, relative string, create bool, mode os.FileMode) (*Directory, string, error) {
	clean, err := validateRelative(relative)
	if err != nil {
		return nil, "", err
	}
	leaf := filepath.Base(clean)
	parent := filepath.Dir(clean)
	rootFile, err := openRoot(root)
	if err != nil {
		return nil, "", err
	}
	current := rootFile
	if parent == "." {
		return &Directory{file: current}, leaf, nil
	}
	for _, component := range strings.Split(parent, string(filepath.Separator)) {
		fd, openErr := unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil && create && errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(int(current.Fd()), component, uint32(mode.Perm())); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = current.Close()
				return nil, "", fmt.Errorf("create directory component %q: %w", component, mkdirErr)
			}
			fd, openErr = unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			_ = current.Close()
			return nil, "", fmt.Errorf("open directory component %q without following symlinks: %w", component, openErr)
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = unix.Close(fd)
			_ = current.Close()
			return nil, "", fmt.Errorf("open directory component %q: invalid file descriptor", component)
		}
		_ = current.Close()
		current = next
	}
	return &Directory{file: current}, leaf, nil
}

// OpenRegular opens a regular leaf in d without following a symlink.
func (d *Directory) OpenRegular(name string) (*os.File, error) {
	if err := validateLeaf(name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open regular file %q without following symlinks: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open regular file %q: invalid file descriptor", name)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect opened file %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%q is not a regular file", name)
	}
	return file, nil
}

// OpenReadWrite opens or creates a regular no-follow leaf for advisory locks.
func (d *Directory) OpenReadWrite(name string, mode os.FileMode) (*os.File, error) {
	if err := validateLeaf(name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open read-write file: invalid file descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%q is not a regular file", name)
	}
	if err := file.Chmod(mode.Perm()); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// CreateTemp creates a random exclusive regular file in d.
func (d *Directory) CreateTemp(prefix string, mode os.FileMode) (*os.File, string, error) {
	for range 100 {
		random := make([]byte, 12)
		if _, err := rand.Read(random); err != nil {
			return nil, "", fmt.Errorf("generate temporary filename: %w", err)
		}
		name := prefix + hex.EncodeToString(random) + ".tmp"
		fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create temporary file: %w", err)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			return nil, "", errors.New("create temporary file: invalid file descriptor")
		}
		if err := file.Chmod(mode.Perm()); err != nil {
			_ = file.Close()
			_ = d.Remove(name)
			return nil, "", fmt.Errorf("set temporary file permissions: %w", err)
		}
		return file, name, nil
	}
	return nil, "", errors.New("could not allocate a unique temporary filename")
}

// ReadDir returns entries from the stable directory descriptor.
func (d *Directory) ReadDir() ([]os.DirEntry, error) {
	return d.file.ReadDir(-1)
}

// Link atomically creates newname as a hard link to oldname and never replaces
// an existing destination.
func (d *Directory) Link(oldname, newname string) error {
	if err := validateLeaf(oldname); err != nil {
		return err
	}
	if err := validateLeaf(newname); err != nil {
		return err
	}
	return unix.Linkat(int(d.file.Fd()), oldname, int(d.file.Fd()), newname, 0)
}

// Rename atomically renames oldname to newname in the stable directory.
func (d *Directory) Rename(oldname, newname string) error {
	if err := validateLeaf(oldname); err != nil {
		return err
	}
	if err := validateLeaf(newname); err != nil {
		return err
	}
	return unix.Renameat(int(d.file.Fd()), oldname, int(d.file.Fd()), newname)
}

// Remove unlinks one non-directory entry in the stable directory.
func (d *Directory) Remove(name string) error {
	if err := validateLeaf(name); err != nil {
		return err
	}
	return unix.Unlinkat(int(d.file.Fd()), name, 0)
}

// Sync flushes directory metadata.
func (d *Directory) Sync() error {
	return unix.Fsync(int(d.file.Fd()))
}

// Close releases the directory descriptor.
func (d *Directory) Close() error {
	if d == nil || d.file == nil {
		return nil
	}
	return d.file.Close()
}

func openRoot(root string) (*os.File, error) {
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve filesystem root %q: %w", root, err)
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root %q: %w", canonical, err)
	}
	file := os.NewFile(uintptr(fd), canonical)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open filesystem root %q: invalid file descriptor", canonical)
	}
	return file, nil
}

func validateRelative(relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("unsafe relative path %q", relative)
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean != relative {
		return "", fmt.Errorf("relative path %q is not canonical", relative)
	}
	return clean, nil
}

func validateLeaf(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsRune(name, 0) {
		return fmt.Errorf("unsafe leaf name %q", name)
	}
	return nil
}
