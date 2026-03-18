package config

import (
	"errors"
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
		validateMtls,
	}

	for _, v := range validators {
		if err := v(cfg); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validateProtocol(cfg *Config) error {
	var errs []error

	if cfg.OkmsID == "" {
		errs = append(errs, errors.New("missing okms id"))
	}
	if cfg.Endpoint == "" {
		errs = append(errs, errors.New("missing endpoint"))
	}
	return errors.Join(errs...)
}

func validateCertPool(cfg *Config) error {
	pool, err := utils.LoadCertPool(cfg.CA)
	if err != nil {
		return err
	}
	cfg.TlsConfig.RootCAs = pool
	return nil
}

func validateMtls(cfg *Config) error {
	certs, err := utils.LoadX509KeyPair(cfg.Auth.Cert, cfg.Auth.Key)
	if err != nil {
		return err
	}
	cfg.TlsConfig.Certificates = certs
	return nil
}
