package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"

	"sigstore-kms-ovhcloud/pkg/utils"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/mocks"
	"github.com/ovh/okms-sdk-go/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// keyManagerMock wires the SDK APIMock into an okmsKeyManager via the embedded okms.Client.API field
func keyManagerMock(apiMock *mocks.APIMock, okmsID uuid.UUID) *okmsKeyManager {
	return &okmsKeyManager{
		client: &okms.Client{API: apiMock},
		okmsID: okmsID,
	}
}

func TestGetPublicKey(t *testing.T) {
	t.Run("client error", func(t *testing.T) {
		expectedError := errors.New("network error")
		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().GetServiceKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, expectedError)

		key, err := keyManagerMock(apiMock, uuid.New()).GetPublicKey(context.Background(), uuid.New())

		assert.Nil(t, key)
		assert.ErrorIs(t, err, expectedError)
		assert.ErrorContains(t, err, "failed to get service key")
	})

	t.Run("nil response", func(t *testing.T) {
		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().GetServiceKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)

		key, err := keyManagerMock(apiMock, uuid.New()).GetPublicKey(context.Background(), uuid.New())

		assert.Nil(t, key)
		assert.ErrorContains(t, err, "public key is missing in the response")
	})

	t.Run("empty keys slice", func(t *testing.T) {
		var emptyKeys []types.JsonWebKeyResponse
		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().GetServiceKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
			&types.GetServiceKeyResponse{Keys: &emptyKeys}, nil,
		)

		key, err := keyManagerMock(apiMock, uuid.New()).GetPublicKey(context.Background(), uuid.New())

		assert.Nil(t, key)
		assert.ErrorContains(t, err, "public key is missing in the response")
	})

	t.Run("invalid JWK", func(t *testing.T) {
		keys := []types.JsonWebKeyResponse{{Kty: types.Oct}}
		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().GetServiceKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
			&types.GetServiceKeyResponse{Keys: &keys}, nil,
		)

		key, err := keyManagerMock(apiMock, uuid.New()).GetPublicKey(context.Background(), uuid.New())

		assert.Nil(t, key)
		assert.ErrorContains(t, err, "failed to convert jwk to public key")
	})

	t.Run("ECDSA key", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		jwk, err := types.NewJsonWebKey(privateKey, nil, "test-public-key")
		require.NoError(t, err)

		okmsID, keyResourceID := uuid.New(), uuid.New()
		keys := []types.JsonWebKeyResponse{jwk}
		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().GetServiceKey(mock.Anything, okmsID, keyResourceID, utils.PtrTo(types.Jwk)).Return(
			&types.GetServiceKeyResponse{Keys: &keys}, nil,
		)

		publicKey, err := keyManagerMock(apiMock, okmsID).GetPublicKey(context.Background(), keyResourceID)

		require.NoError(t, err)
		ecKey, ok := publicKey.(*ecdsa.PublicKey)
		require.True(t, ok, "expected *ecdsa.PublicKey, got %T", publicKey)
		assert.True(t, privateKey.PublicKey.Equal(ecKey))
	})

	t.Run("RSA key", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		require.NoError(t, err)
		jwk, err := types.NewJsonWebKey(privateKey, nil, "test-public-key")
		require.NoError(t, err)

		keys := []types.JsonWebKeyResponse{jwk}
		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().GetServiceKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
			&types.GetServiceKeyResponse{Keys: &keys}, nil,
		)

		publicKey, err := keyManagerMock(apiMock, uuid.New()).GetPublicKey(context.Background(), uuid.New())

		require.NoError(t, err)
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		require.True(t, ok, "expected *rsa.PublicKey, got %T", publicKey)
		assert.True(t, privateKey.PublicKey.Equal(rsaKey))
	})
}

func TestCreateKey(t *testing.T) {
	t.Run("unsupported algorithm", func(t *testing.T) {
		keyManager := keyManagerMock(mocks.NewAPIMock(t), uuid.New())

		keyID, err := keyManager.CreateKey(context.Background(), "my-key", "unsupported")

		assert.Equal(t, uuid.Nil, keyID)
		assert.Error(t, err)
	})

	t.Run("client error", func(t *testing.T) {
		expectedError := errors.New("network error")
		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().
			CreateImportServiceKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil, expectedError)

		keyID, err := keyManagerMock(apiMock, uuid.New()).CreateKey(context.Background(), "my-key", string(types.ES256))

		assert.Equal(t, uuid.Nil, keyID)
		assert.Error(t, err)
	})

	t.Run("nil UUID in response", func(t *testing.T) {
		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().
			CreateImportServiceKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(&types.GetServiceKeyResponse{Id: uuid.Nil}, nil)

		keyID, err := keyManagerMock(apiMock, uuid.New()).CreateKey(context.Background(), "my-key", string(types.ES256))

		assert.Equal(t, uuid.Nil, keyID)
		assert.Error(t, err)
	})

	ecAlgorithmTests := []struct {
		algorithm types.DigitalSignatureAlgorithms
		curve     types.Curves
	}{
		{types.ES256, types.P256},
		{types.ES384, types.P384},
		{types.ES512, types.P521},
	}
	for _, test := range ecAlgorithmTests {
		t.Run(string(test.algorithm), func(t *testing.T) {
			okmsID, expectedID, keyName := uuid.New(), uuid.New(), "test-ec"
			operations := []types.CryptographicUsages{types.Sign, types.Verify}
			expectedRequest := types.CreateImportServiceKeyRequest{
				Curve:      &test.curve,
				Name:       keyName,
				Operations: &operations,
				Type:       utils.PtrTo(types.EC),
			}
			apiMock := mocks.NewAPIMock(t)
			apiMock.EXPECT().
				CreateImportServiceKey(mock.Anything, okmsID, utils.PtrTo(types.Jwk), expectedRequest).
				Return(&types.GetServiceKeyResponse{Id: expectedID}, nil)

			keyID, err := keyManagerMock(apiMock, okmsID).CreateKey(context.Background(), keyName, string(test.algorithm))

			require.NoError(t, err)
			assert.Equal(t, expectedID, keyID)
		})
	}

	rsaAlgorithmTests := []types.DigitalSignatureAlgorithms{
		types.RS256, types.RS384, types.RS512, types.PS256, types.PS384, types.PS512,
	}

	for _, algorithm := range rsaAlgorithmTests {
		t.Run(string(algorithm), func(t *testing.T) {
			okmsID, expectedID, keyName := uuid.New(), uuid.New(), "test-rsa"
			operations := []types.CryptographicUsages{types.Sign, types.Verify}
			expectedRequest := types.CreateImportServiceKeyRequest{
				Name:       keyName,
				Operations: &operations,
				Type:       utils.PtrTo(types.RSA),
				Size:       utils.PtrTo(types.N4096),
			}
			apiMock := mocks.NewAPIMock(t)
			apiMock.EXPECT().
				CreateImportServiceKey(mock.Anything, okmsID, utils.PtrTo(types.Jwk), expectedRequest).
				Return(&types.GetServiceKeyResponse{Id: expectedID}, nil)

			keyID, err := keyManagerMock(apiMock, okmsID).CreateKey(context.Background(), keyName, string(algorithm))

			require.NoError(t, err)
			assert.Equal(t, expectedID, keyID)
		})
	}
}

func TestSign(t *testing.T) {
	t.Run("client error", func(t *testing.T) {
		expectedError := errors.New("signing failed")
		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().
			Sign(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return("", expectedError)

		signature, err := keyManagerMock(apiMock, uuid.New()).Sign(context.Background(), uuid.New(), []byte("digest"), types.ES256)

		assert.Nil(t, signature)
		assert.Error(t, err)
	})

	t.Run("invalid response", func(t *testing.T) {
		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().
			Sign(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return("not-valid", nil)

		signature, err := keyManagerMock(apiMock, uuid.New()).Sign(context.Background(), uuid.New(), []byte("digest"), types.ES256)

		assert.Nil(t, signature)
		assert.ErrorContains(t, err, "failed to decode okms signature")
	})

	t.Run("successful sign", func(t *testing.T) {
		rawSignature := []byte("raw signature")
		encodedSignature := base64.StdEncoding.EncodeToString(rawSignature)

		okmsID, keyID := uuid.New(), uuid.New()
		digest := []byte("test digest")
		algorithm := types.ES256

		apiMock := mocks.NewAPIMock(t)
		apiMock.EXPECT().
			Sign(mock.Anything, okmsID, keyID, utils.PtrTo(types.Raw), algorithm, true, digest).
			Return(encodedSignature, nil)

		signature, err := keyManagerMock(apiMock, okmsID).Sign(context.Background(), keyID, digest, algorithm)

		require.NoError(t, err)
		assert.Equal(t, rawSignature, signature)
	})

	signAlgorithmTests := []types.DigitalSignatureAlgorithms{
		types.ES256, types.ES384, types.ES512,
		types.RS256, types.RS384, types.RS512,
		types.PS256, types.PS384, types.PS512,
	}

	for _, algorithm := range signAlgorithmTests {
		t.Run("successful sign with "+string(algorithm), func(t *testing.T) {
			rawSignature := []byte("signature for " + string(algorithm))
			encodedSignature := base64.StdEncoding.EncodeToString(rawSignature)

			okmsID, keyID := uuid.New(), uuid.New()
			digest := []byte("digest")

			apiMock := mocks.NewAPIMock(t)
			apiMock.EXPECT().
				Sign(mock.Anything, okmsID, keyID, utils.PtrTo(types.Raw), algorithm, true, digest).
				Return(encodedSignature, nil)

			signature, err := keyManagerMock(apiMock, okmsID).Sign(context.Background(), keyID, digest, algorithm)

			require.NoError(t, err)
			assert.Equal(t, rawSignature, signature)
		})
	}
}
