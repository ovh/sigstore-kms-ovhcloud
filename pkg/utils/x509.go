package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

func LoadCertPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("could not load system certificates pool: %w", err)
	}

	if caFile != "" {
		caBundle, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("could not load CA file %q: %w", caFile, err)
		}
		if !pool.AppendCertsFromPEM(caBundle) {
			return nil, fmt.Errorf("invalid CA certificate: %q", caFile)
		}
	}
	return pool, nil
}

func LoadX509KeyPair(clientCert, clientKey string) ([]tls.Certificate, error) {
	var errs []error
	if clientCert == "" {
		errs = append(errs, errors.New("missing client certificate"))
	}
	if clientKey == "" {
		errs = append(errs, errors.New("missing client key"))
	}
	if errs != nil {
		return nil, errors.Join(errs...)
	}

	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("could not load certificate: %v", err)
	}
	return []tls.Certificate{cert}, nil
}
