package utils

import (
	"path/filepath"
	"sigstore-kms-ovhcloud/pkg/testutils"
	"testing"
)

func TestLoadCertPool(t *testing.T) {
	t.Run("empty system pool", func(t *testing.T) {
		pool, err := LoadCertPool("")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pool == nil {
			t.Fatal("expected pool, got nil")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadCertPool("does-not-exist.pem")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("invalid pem", func(t *testing.T) {
		dir := t.TempDir()
		invalidFilePath := filepath.Join(dir, "fake.pem")
		testutils.WriteDataToTempFile(t, "", invalidFilePath, []byte("invalid cert"))

		_, err := LoadCertPool(invalidFilePath)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("valid cert", func(t *testing.T) {
		dir := t.TempDir()
		tc, _ := testutils.GenerateTestCert("ecdsa")
		certFile := testutils.WriteDataToTempFile(t, dir, "cert.pem", tc.CertPEM)

		pool, err := LoadCertPool(certFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pool == nil {
			t.Fatal("expected pool, got nil")
		}
	})
}

func TestLoadX509KeyPair(t *testing.T) {
	t.Run("missing cert and key", func(t *testing.T) {
		_, err := LoadX509KeyPair("", "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("missing cert", func(t *testing.T) {
		dir := t.TempDir()
		key := testutils.WriteDataToTempFile(t, dir, "key.pem", []byte("dummy"))

		_, err := LoadX509KeyPair("", key)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("missing key", func(t *testing.T) {
		dir := t.TempDir()
		cert := testutils.WriteDataToTempFile(t, dir, "cert.pem", []byte("dummy"))

		_, err := LoadX509KeyPair(cert, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("invalid cert and key", func(t *testing.T) {
		dir := t.TempDir()
		cert := testutils.WriteDataToTempFile(t, dir, "cert.pem", []byte("invalid cert"))
		key := testutils.WriteDataToTempFile(t, dir, "key.pem", []byte("invalid key"))

		_, err := LoadX509KeyPair(cert, key)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("valid ECDSA", func(t *testing.T) {
		dir := t.TempDir()
		tc, _ := testutils.GenerateTestCert("ecdsa")
		cert := testutils.WriteDataToTempFile(t, dir, "cert.pem", tc.CertPEM)
		key := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)

		certs, err := LoadX509KeyPair(cert, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("expected 1 cert, got %d", len(certs))
		}
	})

	t.Run("valid RSA", func(t *testing.T) {
		dir := t.TempDir()
		tc, _ := testutils.GenerateTestCert("rsa")
		cert := testutils.WriteDataToTempFile(t, dir, "cert.pem", tc.CertPEM)
		key := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)

		certs, err := LoadX509KeyPair(cert, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("expected 1 cert, got %d", len(certs))
		}
	})
}
