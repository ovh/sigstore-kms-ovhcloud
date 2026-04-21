// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

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
	expectedToken    = "token"
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

	t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
	t.Setenv("KMS_RESTAPI_CERT", expectedCert)
	t.Setenv("KMS_RESTAPI_TYPE", "token")
	t.Setenv("KMS_RESTAPI_OKMSID", expectedID)
	t.Setenv("KMS_RESTAPI_TOKEN", expectedToken)

	err := loadEnvConfig(k, defaultProfile)
	require.NoError(t, err)

	base := "profiles." + defaultProfile + ".restapi."
	assert.Equal(t, expectedEndpoint, k.String(base+"endpoint"))
	assert.Equal(t, expectedCert, k.String(base+"auth.cert"))
	assert.Equal(t, "token", k.String(base+"auth.type"))
	assert.Equal(t, expectedID, k.String(base+"auth.okmsid"))
	assert.Equal(t, expectedToken, k.String(base+"auth.token"))
}

func TestUnmarshalConfig(t *testing.T) {
	k := koanf.New(".")

	_ = k.Set("profiles."+defaultProfile+".restapi.ca", expectedCA)
	_ = k.Set("profiles."+defaultProfile+".restapi.auth.okmsid", expectedID)
	_ = k.Set("profiles."+defaultProfile+".restapi.auth.token", expectedToken)
	_ = k.Set("profiles."+defaultProfile+".restapi.auth.key", expectedKey)

	cfg, err := unmarshalConfig(k, defaultProfile)
	require.NoError(t, err)
	assert.Equal(t, expectedCA, cfg.CA)
	assert.Equal(t, expectedID, cfg.Auth.OkmsID)
	assert.Equal(t, expectedToken, cfg.Auth.Token)
	assert.Equal(t, expectedKey, cfg.Auth.Key)
}

func TestLoadFileConfig(t *testing.T) {
	k := koanf.New(".")

	t.Setenv("HOME", copyTestConfig(t, "valid_mtls_config.yaml"))

	err := loadConfigFile(k)
	require.NoError(t, err)

	profile := k.String("profile")
	assert.Equal(t, "default", profile)

	base := "profiles.default.restapi"
	assert.Equal(t, "https://myserver.acme.com", k.String(base+".endpoint"))
	assert.Equal(t, "/path/to/public-ca.crt", k.String(base+".ca"))
	assert.Equal(t, "/path/to/domain/cert.pem", k.String(base+".auth.cert"))
	assert.Equal(t, "/path/to/domain/key.pem", k.String(base+".auth.key"))
}

func TestNewConfig(t *testing.T) {
	t.Run("invalid mtls config", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", copyTestConfig(t, "valid_mtls_config.yaml"))
		tc, err := testutils.GenerateTestCert("ecdsa")
		require.NoError(t, err)

		certPath := testutils.WriteDataToTempFile(t, dir, "cert.pem", []byte("invalid"))
		keyPath := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)
		caPath := testutils.WriteDataToTempFile(t, dir, "ca.pem", tc.CertPEM)

		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_RESTAPI_CA", caPath)
		t.Setenv("KMS_RESTAPI_CERT", certPath)
		t.Setenv("KMS_RESTAPI_KEY", keyPath)

		_, err = NewConfig()
		assert.Error(t, err)
	})

	t.Run("valid config", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", copyTestConfig(t, "valid_token_config.yaml"))
		tc, err := testutils.GenerateTestCert("ecdsa")
		require.NoError(t, err)

		caPath := testutils.WriteDataToTempFile(t, dir, "ca.pem", tc.CertPEM)

		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_RESTAPI_CA", caPath)

		cfg, err := NewConfig()
		require.NoError(t, err)

		assert.Equal(t, expectedID, cfg.Auth.OkmsID)
		assert.Equal(t, expectedToken, cfg.Auth.Token)
		assert.Equal(t, "token", cfg.Auth.Type)
		assert.Equal(t, expectedEndpoint, cfg.Endpoint)
		assert.Equal(t, caPath, cfg.CA)
		assert.NotNil(t, cfg.TlsConfig)
	})
}
