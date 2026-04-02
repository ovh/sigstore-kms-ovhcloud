package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
