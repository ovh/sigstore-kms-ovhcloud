package signing

import (
	"crypto/tls"
	"fmt"
	"sigstore-kms-ovhcloud/pkg/config"
	"sigstore-kms-ovhcloud/pkg/utils"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
)

// KeyManager TODO: it will be the interface that OkmsKeyManager will implement. Methods have not yet been defined.
type KeyManager interface {
}

type okmsKeyManager struct {
	client *okms.Client
	okmsID uuid.UUID
}

// NewOkmsKeyManager loads a new instance of the okms key manager which contains the client and the okms id.
//
// The tls config in *Config is used to configure the client.
func NewOkmsKeyManager(cfg *config.Config) (KeyManager, error) {
	clientConfig := buildClientConfig(cfg.TlsConfig)
	client, err := okms.NewRestAPIClient(cfg.Endpoint, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("create OKMS client: %w", err)
	}

	okmsID, err := uuid.Parse(cfg.OkmsID)
	if err != nil {
		return nil, fmt.Errorf("invalid okms id: %w", err)
	}

	return &okmsKeyManager{
		client: client,
		okmsID: okmsID,
	}, nil
}

func buildClientConfig(tlsConfig *tls.Config) okms.ClientConfig {
	return okms.ClientConfig{
		Timeout: utils.PtrTo(okms.DefaultHTTPClientTimeout),
		Retry: &okms.RetryConfig{
			RetryMax: 4,
		},
		TlsCfg: tlsConfig,
	}
}
