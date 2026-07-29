//go:build !darwin && !linux

package safefs

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("safe filesystem operations require darwin or linux")

type Directory struct{}

func OpenRegular(string, string) (*os.File, error) { return nil, errUnsupported }
func OpenParent(string, string, bool, os.FileMode) (*Directory, string, error) {
	return nil, "", errUnsupported
}
func (*Directory) OpenRegular(string) (*os.File, error) { return nil, errUnsupported }
func (*Directory) OpenReadWrite(string, os.FileMode) (*os.File, error) {
	return nil, errUnsupported
}
func (*Directory) CreateTemp(string, os.FileMode) (*os.File, string, error) {
	return nil, "", errUnsupported
}
func (*Directory) ReadDir() ([]os.DirEntry, error) { return nil, errUnsupported }
func (*Directory) Link(string, string) error       { return errUnsupported }
func (*Directory) Rename(string, string) error     { return errUnsupported }
func (*Directory) Remove(string) error             { return errUnsupported }
func (*Directory) Sync() error                     { return errUnsupported }
func (*Directory) Close() error                    { return nil }
