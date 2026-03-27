package signing

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"sigstore-kms-ovhcloud/pkg/config"
	"sigstore-kms-ovhcloud/pkg/utils"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/types"
)

type KeyManager interface {
	GetPublicKey(ctx context.Context, keyResourceID uuid.UUID) (crypto.PublicKey, error)
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

func (o *okmsKeyManager) GetPublicKey(ctx context.Context, keyResourceID uuid.UUID) (crypto.PublicKey, error) {
	serviceKey, err := o.client.GetServiceKey(ctx, o.okmsID, keyResourceID, utils.PtrTo(types.Jwk))
	if err != nil {
		return nil, fmt.Errorf("failed to get service key from okms: %w", err)
	}
	if serviceKey == nil || len(*serviceKey.Keys) == 0 {
		return nil, errors.New("public key is missing in the response")
	}

	key := (*serviceKey.Keys)[0]
	publicKey, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to convert jwk to public key: %w", err)
	}
	return publicKey, nil
}
