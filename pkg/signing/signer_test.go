package signing

import (
	"crypto"
	"testing"

	"github.com/ovh/okms-sdk-go/types"
	"github.com/stretchr/testify/assert"
)

type mockKeyManager struct{}

var testKeyManager = &mockKeyManager{}

func TestDefaultAlgorithm(t *testing.T) {
	signerVerifier := NewOkmsSignerVerifier(testKeyManager, "test-key-id", crypto.SHA256)

	result := signerVerifier.DefaultAlgorithm()
	expected := string(types.ES256)

	assert.Equal(t, expected, result)
	assert.Equal(t, "ES256", result)
}

func TestSupportedAlgorithms(t *testing.T) {
	signerVerifier := NewOkmsSignerVerifier(testKeyManager, "test-key-id", crypto.SHA256)

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
	signerVerifier := NewOkmsSignerVerifier(testKeyManager, "test-key-id", crypto.SHA256)

	defaultAlgo := signerVerifier.DefaultAlgorithm()
	supportedAlgos := signerVerifier.SupportedAlgorithms()

	assert.Contains(t, supportedAlgos, defaultAlgo)
}
