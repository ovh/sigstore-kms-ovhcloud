package config

import (
	"errors"
	"fmt"
	"sigstore-kms-ovhcloud/pkg/utils"
)

type validator func(*Config) error

// validateConfig validates the application configuration.
//
// Returns:
//   - error: any configuration errors. If there are multiple errors, they will be grouped into a single error.
func validateConfig(cfg *Config) error {
	var errs []error
	validators := []validator{
		validateProtocol,
		validateCertPool,
		validateAuth,
	}

	for _, v := range validators {
		if err := v(cfg); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validateProtocol(cfg *Config) error {
	if cfg.Endpoint == "" {
		return errors.New("missing endpoint")
	}
	return nil
}

func validateCertPool(cfg *Config) error {
	pool, err := utils.LoadCertPool(cfg.CA)
	if err != nil {
		return err
	}
	cfg.TlsConfig.RootCAs = pool
	return nil
}

func validateAuth(cfg *Config) error {
	switch cfg.Auth.Type {
	case "mtls", "":
		return validateAuthMtls(cfg)
	case "token":
		return validateAuthToken(cfg)
	default:
		return fmt.Errorf("auth type not supported: %s", cfg.Auth.Type)
	}
}

func validateAuthMtls(cfg *Config) error {
	certs, err := utils.LoadX509KeyPair(cfg.Auth.Cert, cfg.Auth.Key)
	if err != nil {
		return err
	}
	cfg.TlsConfig.Certificates = certs
	cfg.Auth.OkmsID, err = utils.GetOkmsIDFromCert(certs[0].Leaf)
	if err != nil {
		return err
	}
	if cfg.Auth.OkmsID == "" {
		return errors.New("missing okms id")
	}
	return nil
}

func validateAuthToken(cfg *Config) error {
	var errs []error

	if cfg.Auth.OkmsID == "" {
		errs = append(errs, errors.New("missing okms id"))
	}
	if cfg.Auth.Token == "" {
		errs = append(errs, errors.New("missing token"))
	}

	return errors.Join(errs...)
}
