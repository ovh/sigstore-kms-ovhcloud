// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package signing

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"os"
	"strings"
	"testing"

	"github.com/ovh/sigstore-kms-ovhcloud/pkg/config"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
	"github.com/ovh/okms-sdk-go/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
The following environment variable must be set:
KMS_INTEGRATION_KEYID - UUID of an existing key on the target KMS instance.
KMS_RESTAPI_OKMSID - OKMS ID

Credentials are loaded from the standard configuration (environment variables or ~/.ovh-kms/okms.yaml).
Or with these environment variables:
KMS_RESTAPI_ENDPOINT - OKMS HTTP Endpoint
KMS_RESTAPI_CA - OKMS HTTP CA (Optional)
KMS_RESTAPI_AUTH_CERT - OKMS HTTP Certificate
KMS_RESTAPI_AUTH_KEY - OKMS HTTP Key
*/

func TestMain(m *testing.M) {
	if os.Getenv("KMS_INTEGRATION_KEYID") == "" {
		panic("KMS_INTEGRATION_KEYID must be set")
	}
	os.Exit(m.Run())
}

func loadSignerVerifier(t *testing.T, keyID string, hashFunc crypto.Hash) (*okmsSignerVerifier, *okmsKeyManager) {
	t.Helper()

	cfg, err := config.NewConfig()
	require.NoError(t, err, "failed to load KMS configuration")

	keyManager, err := NewOkmsKeyManager(cfg)
	require.NoError(t, err, "failed to create KMS key manager")

	signerVerifier := NewOkmsSignerVerifier(keyManager, keyID, hashFunc).(*okmsSignerVerifier)
	require.NotNil(t, signerVerifier)

	return signerVerifier, keyManager.(*okmsKeyManager)
}

func deleteKey(t *testing.T, client *okms.Client, keyResourceID string) {
	t.Helper()

	okmsIDStr := os.Getenv("KMS_RESTAPI_OKMSID")
	okmsID, err := uuid.Parse(okmsIDStr)
	require.NoError(t, err)
	keyID, err := uuid.Parse(keyResourceID)
	require.NoError(t, err)

	err = client.DeactivateServiceKey(t.Context(), okmsID, keyID, types.CessationOfOperation)
	require.NoError(t, err)
	err = client.DeleteServiceKey(t.Context(), okmsID, keyID)
	require.NoError(t, err)
}

func TestNewOkmsSignerVerifier(t *testing.T) {
	keyID := os.Getenv("KMS_INTEGRATION_KEYID")

	cfg, err := config.NewConfig()
	require.NoError(t, err)

	keyManager, err := NewOkmsKeyManager(cfg)
	require.NoError(t, err)

	signerVerifier := NewOkmsSignerVerifier(keyManager, keyID, crypto.SHA256)
	require.NotNil(t, signerVerifier)

	okmsSignerVerifier, ok := signerVerifier.(*okmsSignerVerifier)
	require.True(t, ok)

	assert.Equal(t, okmsSignerVerifier.keyResourceID, keyID)

	okmsKeyManager, ok := okmsSignerVerifier.keyManager.(*okmsKeyManager)
	require.True(t, ok)

	expectedOkmsID, err := uuid.Parse(cfg.Auth.OkmsID)
	require.NoError(t, err)

	assert.Equal(t, okmsKeyManager.okmsID, expectedOkmsID)
}

func TestCreateKey(t *testing.T) {
	signerVerifier, keyManager := loadSignerVerifier(t, uuid.New().String(), crypto.SHA256)

	publicKey, err := signerVerifier.CreateKey(t.Context(), string(types.ES256))
	require.NoError(t, err)
	assert.NotNil(t, publicKey)

	_, ok := publicKey.(*ecdsa.PublicKey)
	assert.True(t, ok)

	deleteKey(t, keyManager.client, signerVerifier.keyResourceID)
}

func TestPublicKey(t *testing.T) {
	keyID := os.Getenv("KMS_INTEGRATION_KEYID")

	signerVerifier, _ := loadSignerVerifier(t, keyID, crypto.SHA256)

	publicKey, err := signerVerifier.PublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, publicKey)
}

func TestSignMessage(t *testing.T) {
	keyID := os.Getenv("KMS_INTEGRATION_KEYID")

	signerVerifier, _ := loadSignerVerifier(t, keyID, crypto.SHA256)

	messageToSign := "secret message"
	signed, err := signerVerifier.SignMessage(strings.NewReader(messageToSign))
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)
}

func TestVerifySignature(t *testing.T) {
	keyID := os.Getenv("KMS_INTEGRATION_KEYID")

	signerVerifier, _ := loadSignerVerifier(t, keyID, crypto.SHA256)

	messageToSign := "secret message"
	signed, err := signerVerifier.SignMessage(strings.NewReader(messageToSign))
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	err = signerVerifier.VerifySignature(bytes.NewReader(signed), strings.NewReader(messageToSign))
	assert.NoError(t, err)
}
