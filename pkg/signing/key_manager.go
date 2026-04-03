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
	CreateKey(ctx context.Context, keyResourceID, algorithm string) (uuid.UUID, error)
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
		return nil, fmt.Errorf("create okms client: %w", err)
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

func (o *okmsKeyManager) CreateKey(ctx context.Context, keyResourceID, algorithm string) (uuid.UUID, error) {
	createKeyRequest := types.CreateImportServiceKeyRequest{
		Name: keyResourceID,
	}

	if err := buildCreateKeyRequest(types.DigitalSignatureAlgorithms(algorithm), &createKeyRequest); err != nil {
		return uuid.Nil, err
	}
	serviceKey, err := o.client.CreateImportServiceKey(ctx, o.okmsID, utils.PtrTo(types.Jwk), createKeyRequest)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create okms key: %w", err)
	}
	if serviceKey == nil || serviceKey.Id == uuid.Nil {
		return uuid.Nil, errors.New("failed to create okms key: empty response from server")
	}
	return serviceKey.Id, nil
}

// buildCreateKeyRequest adds the parameters to the request to be consistent according to the algorithm.
func buildCreateKeyRequest(algorithm types.DigitalSignatureAlgorithms, request *types.CreateImportServiceKeyRequest) error {
	operations := []types.CryptographicUsages{
		types.Sign,
		types.Verify,
	}
	request.Operations = &operations

	switch algorithm {
	case types.ES256, types.ES384, types.ES512:
		curve, err := determineAlgorithmCurve(algorithm)
		if err != nil {
			return err
		}
		request.Curve = &curve
		request.Type = utils.PtrTo(types.EC)
	case types.RS256, types.RS384, types.RS512, types.PS256, types.PS384, types.PS512:
		request.Type = utils.PtrTo(types.RSA)
		request.Size = utils.PtrTo(types.N4096)
	default:
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	return nil
}

// determineAlgorithmCurve returns the curve associated with the algorithm if it is an EC algorithm, otherwise it returns an error.
func determineAlgorithmCurve(algorithm types.DigitalSignatureAlgorithms) (types.Curves, error) {
	switch algorithm {
	case types.ES256:
		return types.P256, nil
	case types.ES384:
		return types.P384, nil
	case types.ES512:
		return types.P521, nil
	default:
		return "", errors.New("invalid algorithm, no curve detected")
	}
}
