//+build linux

package auto

import (
	"crypto/x509"
	"errors"
)

var relativeProfilesPath = "Mozilla/Firefox/Profiles"

func VerifyCert(certPath string) (err error) {
	var cert *x509.Certificate
	if cert, err = readX509Cert(certPath); err != nil {
		return
	}

	_, err = cert.Verify(x509.VerifyOptions{})
	return
}

// Supported whether auto configuration
// is supported for this build
func Supported() bool {
	return false
}

func UninstallAutoProxy(autoURL string) {
	return
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
