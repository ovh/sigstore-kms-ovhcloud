package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKeyManager implements the KeyManager interface
type mockKeyManager struct {
	getPublicKeyFn func(ctx context.Context, keyResourceID uuid.UUID) (crypto.PublicKey, error)
}

var defaultTestKeyManager = &mockKeyManager{}

func (m *mockKeyManager) GetPublicKey(ctx context.Context, keyID uuid.UUID) (crypto.PublicKey, error) {
	if m.getPublicKeyFn != nil {
		return m.getPublicKeyFn(ctx, keyID)
	}
	return nil, nil
}

func TestDefaultAlgorithm(t *testing.T) {
	signerVerifier := NewOkmsSignerVerifier(defaultTestKeyManager, "test-key-id", crypto.SHA256)

	result := signerVerifier.DefaultAlgorithm()
	expected := string(types.ES256)

	assert.Equal(t, expected, result)
	assert.Equal(t, "ES256", result)
}

func TestSupportedAlgorithms(t *testing.T) {
	signerVerifier := NewOkmsSignerVerifier(defaultTestKeyManager, "test-key-id", crypto.SHA256)

	result := signerVerifier.SupportedAlgorithms()
	expected := []string{
		string(types.ES256),
		string(types.ES384),
		string(types.ES512),
		string(types.RS256),
		string(types.RS384),
		string(types.RS512),
		string(types.PS256),
		string(types.PS384),
		string(types.PS512),
	}

	assert.Equal(t, len(expected), len(result))
	assert.ElementsMatch(t, expected, result)
}

func TestDefaultAlgorithm_IsInSupportedList(t *testing.T) {
	signerVerifier := NewOkmsSignerVerifier(defaultTestKeyManager, "test-key-id", crypto.SHA256)

	defaultAlgo := signerVerifier.DefaultAlgorithm()
	supportedAlgos := signerVerifier.SupportedAlgorithms()

	assert.Contains(t, supportedAlgos, defaultAlgo)
}

func TestSigner_PublicKey(t *testing.T) {
	t.Run("invalid key resource id", func(t *testing.T) {
		signerVerifier := NewOkmsSignerVerifier(defaultTestKeyManager, "invalid-uuid", crypto.SHA256)

		publicKey, err := signerVerifier.PublicKey()

		assert.Nil(t, publicKey)
		assert.ErrorContains(t, err, "invalid key id")
	})

	t.Run("key manager error", func(t *testing.T) {
		mock := &mockKeyManager{
			getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
				return nil, errors.New("error in get")
			},
		}
		signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.SHA256)

		publicKey, err := signerVerifier.PublicKey()

		assert.Nil(t, publicKey)
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		expectedPublicKey := &privKey.PublicKey
		var receivedKeyID uuid.UUID
		mock := &mockKeyManager{
			getPublicKeyFn: func(_ context.Context, keyID uuid.UUID) (crypto.PublicKey, error) {
				receivedKeyID = keyID
				return expectedPublicKey, nil
			},
		}
		signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.SHA256)

		publicKey, err := signerVerifier.PublicKey()

		assert.NoError(t, err)
		assert.Equal(t, expectedPublicKey, publicKey)
		assert.Equal(t, uuid.MustParse(signerVerifier.(*okmsSignerVerifier).keyResourceID), receivedKeyID)
	})
}
