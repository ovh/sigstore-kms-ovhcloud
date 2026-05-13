// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const (
	envPrefix         = "KMS_"
	defaultProfile    = "default"
	defaultConfigDir  = ".ovh-kms"
	defaultConfigFile = "okms.yaml"
)

// NewConfig loads the application configuration
//
// First, it attempts to load a configuration file (set by the user or the default one).
// Values from the file can be overridden by environment variables.
//
// Finally, the configuration is validated to ensure it is correct.
//
// Returns:
//   - *Config: the configuration instance.
//   - error: if any step fails. In case of validation errors, they will be grouped into a single error.
func NewConfig() (*Config, error) {
	k := koanf.New(".")

	if err := loadConfigFile(k); err != nil {
		return nil, err
	}
	profile := resolveProfile(k)
	if err := loadEnvConfig(k, profile); err != nil {
		return nil, err
	}
	cfg, err := unmarshalConfig(k, profile)
	if err != nil {
		return nil, err
	}

	cfg.TlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	applyDefaultConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Load the config file from KMS_CONFIG path or with default one.
func loadConfigFile(k *koanf.Koanf) error {
	cfgPath := os.Getenv(envPrefix + "CONFIG")
	if cfgPath == "" {
		homePath, err := os.UserHomeDir()
		if err != nil {
			return nil // non-fatal (variables can be set in the environment)
		}
		cfgPath = filepath.Join(homePath, defaultConfigDir, defaultConfigFile)
	}

	// #nosec G703 -- config path intentionally user-controlled
	if _, err := os.Stat(cfgPath); errors.Is(err, os.ErrNotExist) {
		return nil // non-fatal (variables can be set in the environment)
	}
	if err := k.Load(file.Provider(cfgPath), yaml.Parser()); err != nil {
		return fmt.Errorf("load config file: %w", err)
	}
	return nil
}

func resolveProfile(k *koanf.Koanf) string {
	profile := k.String("profile")
	if profile != "" {
		return profile
	}
	return defaultProfile
}

func unmarshalConfig(k *koanf.Koanf, profile string) (*Config, error) {
	var cfg Config

	path := strings.Join([]string{"profiles", profile, "restapi"}, ".")
	if err := k.Unmarshal(path, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	pluginPath := strings.Join([]string{"profiles", profile, "sigstore-kms-ovhcloud"}, ".")
	if err := k.Unmarshal(pluginPath, &cfg.PluginConfig); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}

func applyDefaultConfig(cfg *Config) {
	if cfg.Auth.Type == "" {
		cfg.Auth.Type = "mtls"
	}

	if cfg.PluginConfig.OnKeyConflict.Strategy == "" {
		cfg.PluginConfig.OnKeyConflict.Strategy = ConflictStrategyError
	}
	if cfg.PluginConfig.OnKeyConflict.Strategy == ConflictStrategyUseMoreRecent && cfg.PluginConfig.OnKeyConflict.MaxKeysToTry == 0 {
		cfg.PluginConfig.OnKeyConflict.MaxKeysToTry = 1
	}
}
