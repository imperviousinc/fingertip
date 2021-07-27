//+build darwin

package main

import (
	"os"
	"path/filepath"
)

func createProcPath(configDir string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}

	exePath := filepath.Dir(exe)
	return exePath, nil
}
