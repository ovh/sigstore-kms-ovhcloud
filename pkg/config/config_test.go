package config

import (
	"os"
	"path/filepath"
	"sigstore-kms-ovhcloud/pkg/testutils"
	"testing"

	"github.com/knadh/koanf/v2"
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
	if err := os.Mkdir(configDir, 0o0755); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join("testdata", filename))
	if err != nil {
		t.Fatal(err)
	}

	configFile := filepath.Join(configDir, "okms.yaml")
	if err := os.WriteFile(configFile, content, 0o0644); err != nil {
		t.Fatal(err)
	}
	return tempDir
}

func TestLoadEnvConfig(t *testing.T) {
	k := koanf.New(".")

	t.Setenv("KMS_HTTP_ENDPOINT", expectedEndpoint)
	t.Setenv("KMS_HTTP_CERT", expectedCert)

	err := loadEnvConfig(k, defaultProfile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	endpoint := k.String("profiles." + defaultProfile + ".http.endpoint")
	if endpoint != expectedEndpoint {
		t.Fatalf("endpoint mismatch: %s", endpoint)
	}

	cert := k.String("profiles." + defaultProfile + ".http.auth.cert")
	if cert != expectedCert {
		t.Fatalf("cert mismatch: %s", cert)
	}
}

func TestUnmarshalConfig(t *testing.T) {
	k := koanf.New(".")

	_ = k.Set("profiles."+defaultProfile+".http.ca", expectedCA)
	_ = k.Set("profiles."+defaultProfile+".http.id", expectedID)
	_ = k.Set("profiles."+defaultProfile+".http.auth.key", expectedKey)

	cfg, err := unmarshalConfig(k, defaultProfile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CA != expectedCA {
		t.Fatalf("ca mismatch: %s", cfg.CA)
	}
	if cfg.OkmsID != expectedID {
		t.Fatalf("id mismatch: %s", cfg.OkmsID)
	}
	if cfg.Auth.Key != expectedKey {
		t.Fatalf("key mismatch: %s", cfg.Auth.Key)
	}
}

func TestLoadFileConfig(t *testing.T) {
	k := koanf.New(".")

	t.Setenv("HOME", copyTestConfig(t, "valid_config.yaml"))

	err := loadConfigFile(k)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	profile := k.String("profile")
	if profile != "default" {
		t.Fatalf("expected default profile, got %s", profile)
	}

	base := "profiles.default.http"
	if k.String(base+".id") != "okms_id" {
		t.Fatalf("id not loaded")
	}
	if k.String(base+".endpoint") != "https://myserver.acme.com" {
		t.Fatalf("endpoint not loaded")
	}
	if k.String(base+".ca") != "/path/to/public-ca.crt" {
		t.Fatalf("ca not loaded")
	}
	if k.String(base+".auth.cert") != "/path/to/domain/cert.pem" {
		t.Fatalf("cert not loaded")
	}
	if k.String(base+".auth.key") != "/path/to/domain/key.pem" {
		t.Fatalf("key not loaded")
	}
}

func TestNewConfig(t *testing.T) {
	t.Run("invalid config", func(t *testing.T) {
		dir := t.TempDir()
		tc, err := testutils.GenerateTestCert("ecdsa")
		if err != nil {
			t.Fatalf("failed to generate cert: %v", err)
		}

		certPath := testutils.WriteDataToTempFile(t, dir, "cert.pem", []byte("invalid"))
		keyPath := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)
		caPath := testutils.WriteDataToTempFile(t, dir, "ca.pem", tc.CertPEM)

		t.Setenv("KMS_HTTP_ID", expectedID)
		t.Setenv("KMS_HTTP_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_HTTP_CA", caPath)
		t.Setenv("KMS_HTTP_CERT", certPath)
		t.Setenv("KMS_HTTP_KEY", keyPath)

		_, err = NewConfig()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("valid config", func(t *testing.T) {
		dir := t.TempDir()
		tc, err := testutils.GenerateTestCert("ecdsa")
		if err != nil {
			t.Fatalf("failed to generate cert: %v", err)
		}

		certPath := testutils.WriteDataToTempFile(t, dir, "cert.pem", tc.CertPEM)
		keyPath := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)
		caPath := testutils.WriteDataToTempFile(t, dir, "ca.pem", tc.CertPEM)

		t.Setenv("KMS_HTTP_ID", expectedID)
		t.Setenv("KMS_HTTP_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_HTTP_CA", caPath)
		t.Setenv("KMS_HTTP_CERT", certPath)
		t.Setenv("KMS_HTTP_KEY", keyPath)

		cfg, err := NewConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.OkmsID != expectedID {
			t.Errorf("expected OkmsID=test-id, got %s", cfg.OkmsID)
		}
		if cfg.Endpoint != expectedEndpoint {
			t.Errorf("unexpected endpoint: %s", cfg.Endpoint)
		}
		if cfg.CA != caPath {
			t.Errorf("unexpected CA: %s", cfg.CA)
		}
		if cfg.Auth.Cert != certPath {
			t.Errorf("unexpected cert path: %s", cfg.Auth.Cert)
		}
		if cfg.Auth.Key != keyPath {
			t.Errorf("unexpected key path: %s", cfg.Auth.Key)
		}
		if cfg.TlsConfig == nil {
			t.Error("TlsConfig should not be nil")
		}
	})
}
