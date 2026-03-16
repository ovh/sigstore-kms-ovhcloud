package signing

import (
	"context"
	"crypto"
	"io"

	"github.com/sigstore/sigstore/pkg/signature"
)

type OkmsSignerVerifier struct {
	KeyResourceID string
	HashFunc      crypto.Hash
}

func (i OkmsSignerVerifier) DefaultAlgorithm() string {
	// TODO implement me
	panic("implement me")
}

func (i OkmsSignerVerifier) SupportedAlgorithms() []string {
	// TODO implement me
	panic("implement me")
}

func (i OkmsSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	// TODO implement me
	panic("implement me")
}

func (i OkmsSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	// TODO implement me
	panic("implement me")
}

func (i OkmsSignerVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	// TODO implement me
	panic("implement me")
}

func (i OkmsSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	// TODO implement me
	panic("implement me")
}

func (i OkmsSignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	// TODO implement me
	panic("implement me")
}
