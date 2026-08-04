package paths

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// ComparisonKey returns a cleaned lexical key for comparing destination paths
// on the named platform. It does not resolve symlinks or require the path to exist.
func ComparisonKey(filename, platform string) (string, error) {
	if platform != "darwin" && platform != "linux" {
		return "", fmt.Errorf("%w: unsupported platform %q", ErrInvalidPath, platform)
	}

	cleaned, err := cleanAbsolute("comparison path", filename)
	if err != nil {
		return "", err
	}
	if platform == "linux" {
		return cleaned, nil
	}
	if !utf8.ValidString(cleaned) {
		return "", fmt.Errorf("%w: comparison path is not valid UTF-8", ErrInvalidPath)
	}

	separator := string(filepath.Separator)
	components := strings.Split(cleaned, separator)
	for index, component := range components {
		decomposed, err := transformPathComponent(norm.NFD, component)
		if err != nil {
			return "", err
		}
		folded, err := transformPathComponent(cases.Fold(), decomposed)
		if err != nil {
			return "", err
		}
		components[index], err = transformPathComponent(norm.NFC, folded)
		if err != nil {
			return "", err
		}
	}
	return strings.Join(components, separator), nil
}

func transformPathComponent(transformer transform.Transformer, component string) (string, error) {
	transformed, consumed, err := transform.String(transformer, component)
	if err != nil {
		return "", fmt.Errorf("%w: transform comparison path component: %v", ErrInvalidPath, err)
	}
	if consumed != len(component) {
		return "", fmt.Errorf("%w: comparison path component was only partially transformed", ErrInvalidPath)
	}
	return transformed, nil
}
