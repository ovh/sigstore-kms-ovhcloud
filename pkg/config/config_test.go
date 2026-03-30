package config

import (
	"os"
	"path/filepath"
	"sigstore-kms-ovhcloud/pkg/testutils"
	"testing"

	"github.com/knadh/koanf/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	expectedEndpoint = "https://kms.example.com"
	expectedCA       = "ca.pem"
	expectedID       = "okms_id"
	expectedKey      = "/key.pem"
	expectedCert     = "/cert.crt"
)

func copyTestConfig(t *testing.T, filename string) string {
	t.Helper()

	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, ".ovh-kms")
	require.NoError(t, os.Mkdir(configDir, 0o0755))

	content, err := os.ReadFile(filepath.Join("testdata", filename))
	require.NoError(t, err)

	configFile := filepath.Join(configDir, "okms.yaml")
	require.NoError(t, os.WriteFile(configFile, content, 0o0644))
	return tempDir
}

func TestLoadEnvConfig(t *testing.T) {
	k := koanf.New(".")

	t.Setenv("KMS_HTTP_ENDPOINT", expectedEndpoint)
	t.Setenv("KMS_HTTP_CERT", expectedCert)

	err := loadEnvConfig(k, defaultProfile)
	require.NoError(t, err)

	endpoint := k.String("profiles." + defaultProfile + ".http.endpoint")
	assert.Equal(t, expectedEndpoint, endpoint)

	cert := k.String("profiles." + defaultProfile + ".http.auth.cert")
	assert.Equal(t, expectedCert, cert)
}

func TestUnmarshalConfig(t *testing.T) {
	k := koanf.New(".")

	_ = k.Set("profiles."+defaultProfile+".http.ca", expectedCA)
	_ = k.Set("profiles."+defaultProfile+".http.id", expectedID)
	_ = k.Set("profiles."+defaultProfile+".http.auth.key", expectedKey)

	cfg, err := unmarshalConfig(k, defaultProfile)
	require.NoError(t, err)
	assert.Equal(t, expectedCA, cfg.CA)
	assert.Equal(t, expectedID, cfg.OkmsID)
	assert.Equal(t, expectedKey, cfg.Auth.Key)
}

func TestLoadFileConfig(t *testing.T) {
	k := koanf.New(".")

	t.Setenv("HOME", copyTestConfig(t, "valid_config.yaml"))

	err := loadConfigFile(k)
	require.NoError(t, err)

	profile := k.String("profile")
	assert.Equal(t, "default", profile)

	base := "profiles.default.http"
	assert.Equal(t, "okms_id", k.String(base+".id"))
	assert.Equal(t, "https://myserver.acme.com", k.String(base+".endpoint"))
	assert.Equal(t, "/path/to/public-ca.crt", k.String(base+".ca"))
	assert.Equal(t, "/path/to/domain/cert.pem", k.String(base+".auth.cert"))
	assert.Equal(t, "/path/to/domain/key.pem", k.String(base+".auth.key"))
}

func TestNewConfig(t *testing.T) {
	t.Run("invalid config", func(t *testing.T) {
		dir := t.TempDir()
		tc, err := testutils.GenerateTestCert("ecdsa")
		require.NoError(t, err)

		certPath := testutils.WriteDataToTempFile(t, dir, "cert.pem", []byte("invalid"))
		keyPath := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)
		caPath := testutils.WriteDataToTempFile(t, dir, "ca.pem", tc.CertPEM)

		t.Setenv("KMS_HTTP_ID", expectedID)
		t.Setenv("KMS_HTTP_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_HTTP_CA", caPath)
		t.Setenv("KMS_HTTP_CERT", certPath)
		t.Setenv("KMS_HTTP_KEY", keyPath)

		_, err = NewConfig()
		assert.Error(t, err)
	})

	t.Run("valid config", func(t *testing.T) {
		dir := t.TempDir()
		tc, err := testutils.GenerateTestCert("ecdsa")
		require.NoError(t, err)

		certPath := testutils.WriteDataToTempFile(t, dir, "cert.pem", tc.CertPEM)
		keyPath := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)
		caPath := testutils.WriteDataToTempFile(t, dir, "ca.pem", tc.CertPEM)

		t.Setenv("KMS_HTTP_ID", expectedID)
		t.Setenv("KMS_HTTP_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_HTTP_CA", caPath)
		t.Setenv("KMS_HTTP_CERT", certPath)
		t.Setenv("KMS_HTTP_KEY", keyPath)

		cfg, err := NewConfig()
		require.NoError(t, err)

		assert.Equal(t, expectedID, cfg.OkmsID)
		assert.Equal(t, expectedEndpoint, cfg.Endpoint)
		assert.Equal(t, caPath, cfg.CA)
		assert.Equal(t, certPath, cfg.Auth.Cert)
		assert.Equal(t, keyPath, cfg.Auth.Key)
		assert.NotNil(t, cfg.TlsConfig)
	})
}
