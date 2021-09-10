//+build linux

package auto

import "errors"

// Supported whether auto configuration
// is supported for this build
func Supported() bool {
	return false
}

// GetProxyStatus checks if the OS is already using a proxy
// and whether its the same as autoURL.
func GetProxyStatus(autoURL string) (ProxyStatus, error) {
	return ProxyStatusNone, errors.New("not supported")
}

func UninstallAutoProxy() error {
	return errors.New("not supported")
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
