package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"strings"
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

func GetOkmsIDFromCert(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions { //
		// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var seq asn1.RawValue
		_, err := asn1.Unmarshal(ext.Value, &seq)
		if err != nil {
			return "", err
		}
		for rest := seq.Bytes; len(rest) > 0; {
			var val asn1.RawValue
			rest, err = asn1.Unmarshal(rest, &val)
			if err != nil {
				return "", err
			}
			if val.Tag != 0 {
				continue
			}

			var oid asn1.ObjectIdentifier
			rem, err := asn1.Unmarshal(val.Bytes, &oid)
			if err != nil {
				return "", err
			}
			if !oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}) {
				continue
			}
			if _, err = asn1.Unmarshal(rem, &val); err != nil {
				return "", err
			}
			var othername string
			if _, err := asn1.Unmarshal(val.Bytes, &othername); err != nil {
				return "", err
			}
			prefix := "okms.domain:"
			if strings.HasPrefix(othername, prefix) {
				return othername[len(prefix):], nil
			}
		}
	}
	return "", errors.New("no okms domain id found")
}
