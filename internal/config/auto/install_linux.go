//+build linux

package auto

import "errors"

// Supported whether auto configuration
// is supported for this build
func Supported() bool {
	return false
}

func UninstallAutoProxy(autoURL string) {
	return nil
}

func InstallAutoProxy(autoURL string) error {
	return errors.New("not supported")
}

func InstallCert(certPath string) error {
	return errors.New("not supported")
}

func UninstallCert(certPath string) error {
	return errors.New("not supported")
}
