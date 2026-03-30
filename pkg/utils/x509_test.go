package utils

import (
	"path/filepath"
	"sigstore-kms-ovhcloud/pkg/testutils"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadCertPool(t *testing.T) {
	t.Run("empty system pool", func(t *testing.T) {
		pool, err := LoadCertPool("")

		require.NoError(t, err)
		assert.NotNil(t, pool)
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadCertPool("does-not-exist.pem")
		assert.Error(t, err)
	})

	t.Run("invalid pem", func(t *testing.T) {
		dir := t.TempDir()
		invalidFilePath := filepath.Join(dir, "fake.pem")
		testutils.WriteDataToTempFile(t, "", invalidFilePath, []byte("invalid cert"))

		_, err := LoadCertPool(invalidFilePath)
		assert.Error(t, err)
	})

	t.Run("valid cert", func(t *testing.T) {
		dir := t.TempDir()
		tc, _ := testutils.GenerateTestCert("ecdsa")
		certFile := testutils.WriteDataToTempFile(t, dir, "cert.pem", tc.CertPEM)

		pool, err := LoadCertPool(certFile)
		require.NoError(t, err)
		assert.NotNil(t, pool)
	})
}

func TestLoadX509KeyPair(t *testing.T) {
	t.Run("missing cert and key", func(t *testing.T) {
		_, err := LoadX509KeyPair("", "")
		assert.Error(t, err)
	})

	t.Run("missing cert", func(t *testing.T) {
		dir := t.TempDir()
		key := testutils.WriteDataToTempFile(t, dir, "key.pem", []byte("dummy"))

		_, err := LoadX509KeyPair("", key)
		assert.Error(t, err)
	})

	t.Run("missing key", func(t *testing.T) {
		dir := t.TempDir()
		cert := testutils.WriteDataToTempFile(t, dir, "cert.pem", []byte("dummy"))

		_, err := LoadX509KeyPair(cert, "")
		assert.Error(t, err)
	})

	t.Run("invalid cert and key", func(t *testing.T) {
		dir := t.TempDir()
		cert := testutils.WriteDataToTempFile(t, dir, "cert.pem", []byte("invalid cert"))
		key := testutils.WriteDataToTempFile(t, dir, "key.pem", []byte("invalid key"))

		_, err := LoadX509KeyPair(cert, key)
		assert.Error(t, err)
	})

	t.Run("valid ECDSA", func(t *testing.T) {
		dir := t.TempDir()
		tc, _ := testutils.GenerateTestCert("ecdsa")
		cert := testutils.WriteDataToTempFile(t, dir, "cert.pem", tc.CertPEM)
		key := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)

		certs, err := LoadX509KeyPair(cert, key)
		require.NoError(t, err)
		assert.Len(t, certs, 1)
	})

	t.Run("valid RSA", func(t *testing.T) {
		dir := t.TempDir()
		tc, _ := testutils.GenerateTestCert("rsa")
		cert := testutils.WriteDataToTempFile(t, dir, "cert.pem", tc.CertPEM)
		key := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)

		certs, err := LoadX509KeyPair(cert, key)
		require.NoError(t, err)
		assert.Len(t, certs, 1)
	})
}
