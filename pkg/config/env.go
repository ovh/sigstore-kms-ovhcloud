package config

import (
	"strings"

	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/v2"
)

// loadEnvConfig overrides config with environment variables.
func loadEnvConfig(k *koanf.Koanf, profile string) error {
	return k.Load(env.Provider(".", env.Opt{
		Prefix:        envPrefix,
		TransformFunc: normalizeEnvVar(profile),
	}), nil)
}

// normalizeEnvVar is a transform function to normalize env var to the corresponding YAML format.
//
// Example: "KMS_HTTP_ENDPOINT" -> "profiles.default.http.endpoint".
func normalizeEnvVar(profile string) func(string, string) (string, any) {
	return func(key, value string) (string, any) {
		key = strings.TrimPrefix(key, envPrefix)
		key = strings.ToLower(key)
		key = strings.ReplaceAll(key, "_", ".")

		parts := strings.SplitN(key, ".", 2)
		if len(parts) == 2 && isAuthField(parts[1]) {
			return buildAuthKey(profile, parts[0], parts[1]), value
		}
		return buildProfileKey(profile, key), value
	}
}

func isAuthField(field string) bool {
	switch field {
	case "cert", "key":
		return true
	default:
		return false
	}
}

// buildAuthKey concatenates strings to correspond to the YAML format: "profiles.default.http.auth.<key>".
func buildAuthKey(profile, connectionType, key string) string {
	return strings.Join([]string{"profiles", profile, connectionType, "auth", key}, ".")
}

// buildProfileKey concatenates strings to correspond to the YAML format: "profiles.default.<key>".
func buildProfileKey(profile, key string) string {
	return strings.Join([]string{"profiles", profile, key}, ".")
}
