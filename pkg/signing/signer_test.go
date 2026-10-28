// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKeyManager implements the KeyManager interface
type mockKeyManager struct {
	getPublicKeyFn func(ctx context.Context, keyResourceID uuid.UUID) (crypto.PublicKey, error)
	createKeyFn    func(ctx context.Context, keyResourceID uuid.UUID, algorithm string) (uuid.UUID, error)
	signFn         func(ctx context.Context, keyID uuid.UUID, digest []byte, algorithm types.DigitalSignatureAlgorithms) ([]byte, error)
	verifyFn       func(ctx context.Context, keyResourceID uuid.UUID, digest []byte, algorithm types.DigitalSignatureAlgorithms, signature []byte) error
}

func (m *mockKeyManager) GetPublicKey(ctx context.Context, keyID uuid.UUID) (crypto.PublicKey, error) {
	if m.getPublicKeyFn != nil {
		return m.getPublicKeyFn(ctx, keyID)
	}
	return nil, nil
}

func (m *mockKeyManager) CreateKey(ctx context.Context, keyResourceID uuid.UUID, algorithm string) (uuid.UUID, error) {
	if m.createKeyFn != nil {
		return m.createKeyFn(ctx, keyResourceID, algorithm)
	}
	return keyResourceID, nil
}

func (m *mockKeyManager) Sign(ctx context.Context, keyID uuid.UUID, digest []byte, algorithm types.DigitalSignatureAlgorithms) ([]byte, error) {
	if m.signFn != nil {
		return m.signFn(ctx, keyID, digest, algorithm)
	}
	return nil, nil
}

func (m *mockKeyManager) Verify(ctx context.Context, keyResourceID uuid.UUID, digest []byte, algorithm types.DigitalSignatureAlgorithms, signature []byte) error {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, keyResourceID, digest, algorithm, signature)
	}
	return nil
}

var defaultTestKeyManager = &mockKeyManager{}

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
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		expectedPublicKey := &privateKey.PublicKey
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

func TestSigner_CreateKey(t *testing.T) {
	t.Run("invalid key resource id", func(t *testing.T) {
		signerVerifier := NewOkmsSignerVerifier(defaultTestKeyManager, "invalid-uuid", crypto.SHA256)

		publicKey, err := signerVerifier.CreateKey(context.Background(), string(types.ES256))

		assert.Nil(t, publicKey)
		assert.Error(t, err)
	})

	t.Run("key manager error", func(t *testing.T) {
		mock := &mockKeyManager{
			createKeyFn: func(_ context.Context, _ uuid.UUID, _ string) (uuid.UUID, error) {
				return uuid.Nil, errors.New("error in create")
			},
		}
		signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.SHA256)

		publicKey, err := signerVerifier.CreateKey(context.Background(), string(types.ES256))

		assert.Nil(t, publicKey)
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		expectedPublicKey := &privateKey.PublicKey
		keyResourceID := uuid.New().String()
		var receivedKeyID uuid.UUID
		mock := &mockKeyManager{
			getPublicKeyFn: func(ctx context.Context, keyResourceID uuid.UUID) (crypto.PublicKey, error) {
				receivedKeyID = keyResourceID
				return expectedPublicKey, nil
			},
		}
		signerVerifier := NewOkmsSignerVerifier(mock, keyResourceID, crypto.SHA256)

		publicKey, err := signerVerifier.CreateKey(context.Background(), string(types.ES256))

		require.NoError(t, err)
		assert.Equal(t, expectedPublicKey, publicKey)
		expectedUUID := uuid.MustParse(keyResourceID)
		assert.Equal(t, expectedUUID, receivedKeyID)
		assert.Equal(t, expectedUUID.String(), signerVerifier.(*okmsSignerVerifier).keyResourceID)
	})
}

func TestSigner_SignMessage(t *testing.T) {
	t.Run("invalid key resource id", func(t *testing.T) {
		signerVerifier := NewOkmsSignerVerifier(defaultTestKeyManager, "invalid-uuid", crypto.SHA256)

		sig, err := signerVerifier.SignMessage(strings.NewReader("test message"))

		assert.Nil(t, sig)
		assert.ErrorContains(t, err, "invalid key id")
	})

	t.Run("Sign error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		expectedError := errors.New("sign error")
		mock := &mockKeyManager{
			getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
				return &privateKey.PublicKey, nil
			},
			signFn: func(_ context.Context, _ uuid.UUID, _ []byte, _ types.DigitalSignatureAlgorithms) ([]byte, error) {
				return nil, expectedError
			},
		}
		signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.SHA256)

		sig, err := signerVerifier.SignMessage(strings.NewReader("test message"))

		assert.Nil(t, sig)
		assert.ErrorIs(t, err, expectedError)
	})

	successCases := []struct {
		name              string
		hashFunc          crypto.Hash
		buildKey          func(t *testing.T) crypto.PublicKey
		signOpts          []signature.SignOption
		expectedAlgorithm types.DigitalSignatureAlgorithms
	}{
		{
			name:     "ES256",
			hashFunc: crypto.SHA256,
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.ES256,
		},
		{
			name:     "ES384",
			hashFunc: crypto.SHA384,
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.ES384,
		},
		{
			name:     "ES512",
			hashFunc: crypto.SHA512,
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.ES512,
		},
		{
			name:     "RS256",
			hashFunc: crypto.SHA256,
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := rsa.GenerateKey(rand.Reader, 4096)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.RS256,
		},
		{
			name:     "RS384",
			hashFunc: crypto.SHA384,
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := rsa.GenerateKey(rand.Reader, 4096)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.RS384,
		},
		{
			name:     "RS512",
			hashFunc: crypto.SHA512,
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := rsa.GenerateKey(rand.Reader, 4096)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.RS512,
		},
		{
			name:     "PS256",
			hashFunc: crypto.SHA256,
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := rsa.GenerateKey(rand.Reader, 4096)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			signOpts:          []signature.SignOption{options.WithCryptoSignerOpts(&rsa.PSSOptions{Hash: crypto.SHA256})},
			expectedAlgorithm: types.PS256,
		},
		{
			name:     "PS384",
			hashFunc: crypto.SHA384,
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := rsa.GenerateKey(rand.Reader, 4096)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			signOpts:          []signature.SignOption{options.WithCryptoSignerOpts(&rsa.PSSOptions{Hash: crypto.SHA384})},
			expectedAlgorithm: types.PS384,
		},
		{
			name:     "PS512",
			hashFunc: crypto.SHA512,
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := rsa.GenerateKey(rand.Reader, 4096)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			signOpts:          []signature.SignOption{options.WithCryptoSignerOpts(&rsa.PSSOptions{Hash: crypto.SHA512})},
			expectedAlgorithm: types.PS512,
		},
	}

	for _, test := range successCases {
		t.Run("success with "+test.name, func(t *testing.T) {
			publicKey := test.buildKey(t)
			expectedSignature := []byte("expectedAlgorithm-signature")
			var receivedAlgorithm types.DigitalSignatureAlgorithms

			mock := &mockKeyManager{
				getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
					return publicKey, nil
				},
				signFn: func(_ context.Context, _ uuid.UUID, _ []byte, algorithm types.DigitalSignatureAlgorithms) ([]byte, error) {
					receivedAlgorithm = algorithm
					return expectedSignature, nil
				},
			}
			signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), test.hashFunc)

			sig, err := signerVerifier.SignMessage(strings.NewReader("test message"), test.signOpts...)

			require.NoError(t, err)
			assert.Equal(t, test.expectedAlgorithm, receivedAlgorithm)
			assert.Equal(t, expectedSignature, sig)
		})
	}
}

func TestDefaultHashFuncForKey(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		publicKey crypto.PublicKey
		expected  crypto.Hash
	}{
		{name: "P-256", publicKey: &p256Key.PublicKey, expected: crypto.SHA256},
		{name: "P-384", publicKey: &p384Key.PublicKey, expected: crypto.SHA384},
		{name: "P-521", publicKey: &p521Key.PublicKey, expected: crypto.SHA512},
		{name: "RSA", publicKey: &rsaKey.PublicKey, expected: crypto.SHA256},
		{name: "nil", publicKey: nil, expected: crypto.SHA256},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, defaultHashFuncForKey(test.publicKey))
		})
	}
}

func TestSigner_SignMessage_WithUnsetHashFunc(t *testing.T) {
	testCases := []struct {
		name              string
		buildKey          func(t *testing.T) crypto.PublicKey
		expectedAlgorithm types.DigitalSignatureAlgorithms
		expectedHashFunc  crypto.Hash
	}{
		{
			name: "P-256 key defaults to SHA-256",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.ES256,
			expectedHashFunc:  crypto.SHA256,
		},
		{
			name: "P-384 key defaults to SHA-384",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.ES384,
			expectedHashFunc:  crypto.SHA384,
		},
		{
			name: "P-521 key defaults to SHA-512",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.ES512,
			expectedHashFunc:  crypto.SHA512,
		},
		{
			name: "RSA key defaults to SHA-256",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.RS256,
			expectedHashFunc:  crypto.SHA256,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			publicKey := test.buildKey(t)
			var receivedDigest []byte
			var receivedAlgorithm types.DigitalSignatureAlgorithms
			mock := &mockKeyManager{
				getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
					return publicKey, nil
				},
				signFn: func(_ context.Context, _ uuid.UUID, digest []byte, algorithm types.DigitalSignatureAlgorithms) ([]byte, error) {
					receivedDigest = digest
					receivedAlgorithm = algorithm
					return []byte("signature"), nil
				},
			}
			signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.Hash(0))

			sig, err := signerVerifier.SignMessage(strings.NewReader("test message"))

			require.NoError(t, err)
			assert.Equal(t, []byte("signature"), sig)
			assert.Len(t, receivedDigest, test.expectedHashFunc.Size())
			assert.Equal(t, test.expectedAlgorithm, receivedAlgorithm)
		})
	}
}

func TestSigner_VerifySignature_WithUnsetHashFunc(t *testing.T) {
	testCases := []struct {
		name              string
		buildKey          func(t *testing.T) crypto.PublicKey
		expectedAlgorithm types.DigitalSignatureAlgorithms
		expectedHashFunc  crypto.Hash
	}{
		{
			name: "P-256 key defaults to SHA-256",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.ES256,
			expectedHashFunc:  crypto.SHA256,
		},
		{
			name: "P-384 key defaults to SHA-384",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.ES384,
			expectedHashFunc:  crypto.SHA384,
		},
		{
			name: "P-521 key defaults to SHA-512",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.ES512,
			expectedHashFunc:  crypto.SHA512,
		},
		{
			name: "RSA key defaults to SHA-256",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			expectedAlgorithm: types.RS256,
			expectedHashFunc:  crypto.SHA256,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			publicKey := test.buildKey(t)
			var receivedDigest []byte
			var receivedAlgorithm types.DigitalSignatureAlgorithms
			mock := &mockKeyManager{
				getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
					return publicKey, nil
				},
				verifyFn: func(_ context.Context, _ uuid.UUID, digest []byte, algorithm types.DigitalSignatureAlgorithms, _ []byte) error {
					receivedDigest = digest
					receivedAlgorithm = algorithm
					return nil
				},
			}
			signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.Hash(0))

			err := signerVerifier.VerifySignature(bytes.NewReader([]byte("signature")), bytes.NewReader([]byte("test message")))

			require.NoError(t, err)
			assert.Len(t, receivedDigest, test.expectedHashFunc.Size())
			assert.Equal(t, test.expectedAlgorithm, receivedAlgorithm)
		})
	}

	t.Run("digest provided without hash function", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		expectedDigest := make([]byte, crypto.SHA512.Size())
		var receivedDigest []byte
		var receivedAlgorithm types.DigitalSignatureAlgorithms
		mock := &mockKeyManager{
			getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
				return &privateKey.PublicKey, nil
			},
			verifyFn: func(_ context.Context, _ uuid.UUID, digest []byte, algorithm types.DigitalSignatureAlgorithms, _ []byte) error {
				receivedDigest = digest
				receivedAlgorithm = algorithm
				return nil
			},
		}
		signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.Hash(0))

		err = signerVerifier.VerifySignature(bytes.NewReader([]byte("signature")), bytes.NewReader([]byte{}), options.WithDigest(expectedDigest))

		require.NoError(t, err)
		assert.Equal(t, expectedDigest, receivedDigest)
		assert.Equal(t, types.ES512, receivedAlgorithm)
	})
}

func TestSigner_SignMessage_InvalidHashFuncForKey(t *testing.T) {
	testCases := []struct {
		name        string
		buildKey    func(t *testing.T) crypto.PublicKey
		hashFunc    crypto.Hash
		expectedErr string
	}{
		{
			name: "P-256 with SHA-384",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			hashFunc:    crypto.SHA384,
			expectedErr: "unsupported hash function SHA-384 for P-256 key: expected SHA-256",
		},
		{
			name: "P-256 with SHA-512",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			hashFunc:    crypto.SHA512,
			expectedErr: "unsupported hash function SHA-512 for P-256 key: expected SHA-256",
		},
		{
			name: "P-384 with SHA-256",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			hashFunc:    crypto.SHA256,
			expectedErr: "unsupported hash function SHA-256 for P-384 key: expected SHA-384",
		},
		{
			name: "P-521 with SHA-256",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			hashFunc:    crypto.SHA256,
			expectedErr: "unsupported hash function SHA-256 for P-521 key: expected SHA-512",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			publicKey := test.buildKey(t)
			signCalled := false
			mock := &mockKeyManager{
				getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
					return publicKey, nil
				},
				signFn: func(_ context.Context, _ uuid.UUID, _ []byte, _ types.DigitalSignatureAlgorithms) ([]byte, error) {
					signCalled = true
					return nil, nil
				},
			}
			signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), test.hashFunc)

			sig, err := signerVerifier.SignMessage(strings.NewReader("test message"))

			assert.Nil(t, sig)
			assert.ErrorContains(t, err, test.expectedErr)
			assert.False(t, signCalled, "the KMS should not be called")
		})
	}
}

func TestSigner_VerifySignature_InvalidHashFuncForKey(t *testing.T) {
	testCases := []struct {
		name        string
		buildKey    func(t *testing.T) crypto.PublicKey
		hashFunc    crypto.Hash
		expectedErr string
	}{
		{
			name: "P-256 with SHA-384",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			hashFunc:    crypto.SHA384,
			expectedErr: "unsupported hash function SHA-384 for P-256 key: expected SHA-256",
		},
		{
			name: "P-384 with SHA-512",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			hashFunc:    crypto.SHA512,
			expectedErr: "unsupported hash function SHA-512 for P-384 key: expected SHA-384",
		},
		{
			name: "P-521 with SHA-384",
			buildKey: func(t *testing.T) crypto.PublicKey {
				t.Helper()
				privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				return &privKey.PublicKey
			},
			hashFunc:    crypto.SHA384,
			expectedErr: "unsupported hash function SHA-384 for P-521 key: expected SHA-512",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			publicKey := test.buildKey(t)
			verifyCalled := false
			mock := &mockKeyManager{
				getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
					return publicKey, nil
				},
				verifyFn: func(_ context.Context, _ uuid.UUID, _ []byte, _ types.DigitalSignatureAlgorithms, _ []byte) error {
					verifyCalled = true
					return nil
				},
			}
			signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), test.hashFunc)

			err := signerVerifier.VerifySignature(bytes.NewReader([]byte("signature")), bytes.NewReader([]byte("test message")))

			assert.ErrorContains(t, err, test.expectedErr)
			assert.False(t, verifyCalled, "the KMS should not be called")
		})
	}
}

func TestSigner_VerifySignature(t *testing.T) {
	t.Run("invalid key resource id", func(t *testing.T) {
		signerVerifier := NewOkmsSignerVerifier(defaultTestKeyManager, "invalid-uuid", crypto.SHA256)

		err := signerVerifier.VerifySignature(bytes.NewReader([]byte("test signature")), bytes.NewReader([]byte("test message")))

		assert.ErrorContains(t, err, "invalid key id")
	})

	t.Run("signature reader error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		readerError := errors.New("read failure")
		mock := &mockKeyManager{
			getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
				return &privateKey.PublicKey, nil
			},
		}
		signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.SHA256)

		err = signerVerifier.VerifySignature(iotest.ErrReader(readerError), bytes.NewReader([]byte("test message")))

		assert.ErrorIs(t, err, readerError)
	})

	t.Run("Verify error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		expectedError := errors.New("verify failed")
		mock := &mockKeyManager{
			getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
				return &privateKey.PublicKey, nil
			},
			verifyFn: func(_ context.Context, _ uuid.UUID, _ []byte, _ types.DigitalSignatureAlgorithms, _ []byte) error {
				return expectedError
			},
		}
		signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.SHA256)

		err = signerVerifier.VerifySignature(bytes.NewReader([]byte("test signature")), bytes.NewReader([]byte("test message")))

		assert.Error(t, err)
	})

	t.Run("success with ES256", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		sigBytes := []byte("fake-signature")
		var receivedDigest []byte
		var receivedAlgorithm types.DigitalSignatureAlgorithms
		var receivedSig []byte
		mock := &mockKeyManager{
			getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
				return &privateKey.PublicKey, nil
			},
			verifyFn: func(_ context.Context, _ uuid.UUID, digest []byte, algorithm types.DigitalSignatureAlgorithms, sig []byte) error {
				receivedDigest = digest
				receivedAlgorithm = algorithm
				receivedSig = sig
				return nil
			},
		}
		signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.SHA256)

		err = signerVerifier.VerifySignature(bytes.NewReader(sigBytes), bytes.NewReader([]byte("test message")))

		require.NoError(t, err)
		assert.NotEmpty(t, receivedDigest)
		assert.Equal(t, types.ES256, receivedAlgorithm)
		assert.Equal(t, sigBytes, receivedSig)
	})

	t.Run("success with RS512", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		require.NoError(t, err)

		var receivedAlgorithm types.DigitalSignatureAlgorithms
		mock := &mockKeyManager{
			getPublicKeyFn: func(_ context.Context, _ uuid.UUID) (crypto.PublicKey, error) {
				return &privateKey.PublicKey, nil
			},
			verifyFn: func(_ context.Context, _ uuid.UUID, _ []byte, algorithm types.DigitalSignatureAlgorithms, _ []byte) error {
				receivedAlgorithm = algorithm
				return nil
			},
		}
		signerVerifier := NewOkmsSignerVerifier(mock, uuid.New().String(), crypto.SHA512)

		err = signerVerifier.VerifySignature(bytes.NewReader([]byte("test signature")), bytes.NewReader([]byte("test message")))

		require.NoError(t, err)
		assert.Equal(t, types.RS512, receivedAlgorithm)
	})
}
