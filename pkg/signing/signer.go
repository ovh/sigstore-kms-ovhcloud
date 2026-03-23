package signing

import (
	"context"
	"crypto"
	"io"

	"github.com/ovh/okms-sdk-go/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

//lint:ignore U1000 Ignore for now to prevent the linter from returning an error
var okmsSupportedHashFuncs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}

var okmsSupportedAlgorithms = []types.DigitalSignatureAlgorithms{
	types.ES256,
	types.ES384,
	types.ES512,
	types.RS256,
	types.RS384,
	types.RS512,
	types.PS256,
	types.PS384,
	types.PS512,
}

const defaultAlgorithm = types.ES256

type okmsSignerVerifier struct {
	keyManager    KeyManager
	keyResourceID string
	hashFunc      crypto.Hash
}

// NewOkmsSignerVerifier returns an instance of okmsSignerVerifier which is an implementation of kms.SignerVerifier.
func NewOkmsSignerVerifier(km KeyManager, keyResourceID string, hashFunc crypto.Hash) kms.SignerVerifier {
	return &okmsSignerVerifier{
		keyManager:    km,
		keyResourceID: keyResourceID,
		hashFunc:      hashFunc,
	}
}

// DefaultAlgorithm returns the default algorithm for the signer.
func (o okmsSignerVerifier) DefaultAlgorithm() string {
	return string(defaultAlgorithm)
}

// SupportedAlgorithms returns the supported algorithms for the signer.
func (o okmsSignerVerifier) SupportedAlgorithms() []string {
	s := make([]string, len(okmsSupportedAlgorithms))

	for i := range okmsSupportedAlgorithms {
		s[i] = string(okmsSupportedAlgorithms[i])
	}
	return s
}

func (o okmsSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	// TODO implement me
	panic("implement me")
}

func (o okmsSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	// TODO implement me
	panic("implement me")
}

func (o okmsSignerVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	// TODO implement me
	panic("implement me")
}

func (o okmsSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	// TODO implement me
	panic("implement me")
}

func (o okmsSignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	// TODO implement me
	panic("implement me")
}
