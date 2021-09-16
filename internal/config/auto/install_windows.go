//+build windows

package auto

// crypto API usage based on https://github.com/FiloSottile/mkcert/blob/master/truststore_windows.go

import (
	"crypto/x509"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"math/big"
	"syscall"
	"unsafe"
)

var (
	modcrypt32                           = syscall.NewLazyDLL("crypt32.dll")
	procCertAddEncodedCertificateToStore = modcrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertCloseStore                   = modcrypt32.NewProc("CertCloseStore")
	procCertDeleteCertificateFromStore   = modcrypt32.NewProc("CertDeleteCertificateFromStore")
	procCertDuplicateCertificateContext  = modcrypt32.NewProc("CertDuplicateCertificateContext")
	procCertEnumCertificatesInStore      = modcrypt32.NewProc("CertEnumCertificatesInStore")
	procCertOpenSystemStoreW             = modcrypt32.NewProc("CertOpenSystemStoreW")
)

type windowsRootStore uintptr

// Supported whether auto configuration
// is supported for this build
func Supported() bool {
	return true
}

func getProxyStatus(autoURL string) (ProxyStatus, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return ProxyStatusNone, err
	}
	defer k.Close()

	value, _, _ := k.GetStringValue("AutoConfigURL")
	if equalURL(autoURL, value) {
		return ProxyStatusInstalled, nil
	}

	if value == "" {
		return ProxyStatusNone, nil
	}

	return ProxyStatusConflict, nil
}

func UninstallAutoProxy(autoURL string) {
	if status, err := getProxyStatus(autoURL); err != nil || status == ProxyStatusConflict {
		return
	}

	k, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.ALL_ACCESS)
	if err != nil {
		return
	}
	defer k.Close()

	_ = k.DeleteValue("AutoConfigURL")
	return
}

func InstallAutoProxy(autoURL string) error {
	status, err := getProxyStatus(autoURL)
	if err != nil {
		return fmt.Errorf("failed reading proxy status")
	}
	if status == ProxyStatusConflict {
		return fmt.Errorf("auto configuration failed your OS has existing proxy settings")
	}
	if status == ProxyStatusInstalled {
		return nil
	}

	k, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed reading from registry: %v", err)
	}
	defer k.Close()

	if err = k.SetStringValue("AutoConfigURL", autoURL); err != nil {
		return fmt.Errorf("failed setting AutoConfigURL: %v", err)
	}
	return nil
}

func InstallCert(certPath string) error {
	// Load cert
	cert, err := readPEM(certPath)
	if err != nil {
		return err
	}

	// Open root store
	store, err := openWindowsRootStore()
	if err != nil {
		return err
	}
	defer store.close()
	// Add cert
	if err := store.addCert(cert); err != nil {
		return err
	}

	return nil
}

func UninstallCert(certPath string) error {
	cert, err := readX509Cert(certPath)
	if err != nil {
		return err
	}

	// We'll just remove all certs with the same serial number
	// Open root store
	store, err := openWindowsRootStore()
	if err != nil {
		return err
	}
	defer store.close()

	// Do the deletion
	deletedAny, err := store.deleteCertsWithSerial(cert.SerialNumber)
	if err == nil && !deletedAny {
		err = fmt.Errorf("no certs found")
	}

	if err != nil {
		return fmt.Errorf("failed deleting cert: %v", err)
	}

	return nil
}

func openWindowsRootStore() (windowsRootStore, error) {
	rootStr, err := syscall.UTF16PtrFromString("ROOT")
	if err != nil {
		return 0, err
	}
	store, _, err := procCertOpenSystemStoreW.Call(0, uintptr(unsafe.Pointer(rootStr)))
	if store != 0 {
		return windowsRootStore(store), nil
	}
	return 0, fmt.Errorf("failed opening windows root store: %v", err)
}

func (w windowsRootStore) close() error {
	ret, _, err := procCertCloseStore.Call(uintptr(w), 0)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("failed closing windows root store: %v", err)
}

func (w windowsRootStore) addCert(cert []byte) error {
	ret, _, err := procCertAddEncodedCertificateToStore.Call(
		uintptr(w), // HCERTSTORE hCertStore
		uintptr(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING), // DWORD dwCertEncodingType
		uintptr(unsafe.Pointer(&cert[0])),                              // const BYTE *pbCertEncoded
		uintptr(len(cert)),                                             // DWORD cbCertEncoded
		3,                                                              // DWORD dwAddDisposition (CERT_STORE_ADD_REPLACE_EXISTING is 3)
		0,                                                              // PCCERT_CONTEXT *ppCertContext
	)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("failed adding cert: %v", err)
}

func (w windowsRootStore) deleteCertsWithSerial(serial *big.Int) (bool, error) {
	// Go over each, deleting the ones we find
	var cert *syscall.CertContext
	deletedAny := false
	for {
		// Next enum
		certPtr, _, err := procCertEnumCertificatesInStore.Call(uintptr(w), uintptr(unsafe.Pointer(cert)))
		if cert = (*syscall.CertContext)(unsafe.Pointer(certPtr)); cert == nil {
			if errno, ok := err.(syscall.Errno); ok && errno == 0x80092004 {
				break
			}
			return deletedAny, fmt.Errorf("failed enumerating certs: %v", err)
		}
		// Parse cert
		certBytes := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:cert.Length]
		parsedCert, err := x509.ParseCertificate(certBytes)
		// We'll just ignore parse failures for now
		if err == nil && parsedCert.SerialNumber != nil && parsedCert.SerialNumber.Cmp(serial) == 0 {
			// Duplicate the context so it doesn't stop the enum when we delete it
			dupCertPtr, _, err := procCertDuplicateCertificateContext.Call(uintptr(unsafe.Pointer(cert)))
			if dupCertPtr == 0 {
				return deletedAny, fmt.Errorf("failed duplicating context: %v", err)
			}
			if ret, _, err := procCertDeleteCertificateFromStore.Call(dupCertPtr); ret == 0 {
				return deletedAny, fmt.Errorf("failed deleting certificate: %v", err)
			}
			deletedAny = true
		}
	}
	return deletedAny, nil
}
