package config

import "crypto/tls"

type ConflictStrategy string

const (
	ConflictStrategyError         ConflictStrategy = "error"
	ConflictStrategyUseMoreRecent ConflictStrategy = "use-more-recent"
)

type Config struct {
	Endpoint     string     `koanf:"endpoint"`
	CA           string     `koanf:"ca"`
	Auth         AuthConfig `koanf:"auth"`
	PluginConfig PluginConfig
	TlsConfig    *tls.Config
}

type AuthConfig struct {
	Type   string `koanf:"type"`
	Cert   string `koanf:"cert"`
	Key    string `koanf:"key"`
	OkmsID string `koanf:"okms-id"`
	Token  string `koanf:"token"`
}

type PluginConfig struct {
	OnKeyConflict OnKeyConflictConfig `koanf:"on-key-conflict"`
}

type OnKeyConflictConfig struct {
	Strategy     ConflictStrategy `koanf:"strategy"`
	MaxKeysToTry int              `koanf:"max-keys-to-try"`
}
