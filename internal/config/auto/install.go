package auto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

type ProxyStatus int

const (
	ProxyStatusNone      ProxyStatus = 0
	ProxyStatusInstalled             = 1
	ProxyStatusConflict              = 2
)

func VerifyCert(certPath string) (err error) {
	var cert *x509.Certificate
	if cert, err = readX509Cert(certPath); err != nil {
		return
	}

	_, err = cert.Verify(x509.VerifyOptions{})
	return
}

func readPEM(certPath string) ([]byte, error) {
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed reading root certificate: %v", err)
	}

	// Decode PEM
	certBlock, _ := pem.Decode(cert)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed decoding cert invalid PEM data")
	}

	return certBlock.Bytes, nil
}

func readX509Cert(certPath string) (*x509.Certificate, error) {
	cert, err := readPEM(certPath)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	return c, nil
}
