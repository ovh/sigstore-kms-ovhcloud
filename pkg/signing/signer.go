// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go/types"
	"github.com/ovh/sigstore-kms-ovhcloud/pkg/config"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

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
	keyManager      KeyManager
	keyResourceID   string
	keyResourceName string
	hashFunc        crypto.Hash
	pluginConfig    config.PluginConfig
}

// NewOkmsSignerVerifier returns an instance of okmsSignerVerifier which is an implementation of kms.SignerVerifier.
func NewOkmsSignerVerifier(km KeyManager, keyResourceName string, hashFunc crypto.Hash, pluginConfig config.PluginConfig) kms.SignerVerifier {
	return &okmsSignerVerifier{
		keyManager:      km,
		keyResourceName: keyResourceName,
		hashFunc:        hashFunc,
		pluginConfig:    pluginConfig,
	}
}

// DefaultAlgorithm returns the default algorithm for the signer.
func (o *okmsSignerVerifier) DefaultAlgorithm() string {
	return string(defaultAlgorithm)
}

// SupportedAlgorithms returns the supported algorithms for the signer.
func (o *okmsSignerVerifier) SupportedAlgorithms() []string {
	s := make([]string, len(okmsSupportedAlgorithms))

	for i := range okmsSupportedAlgorithms {
		s[i] = string(okmsSupportedAlgorithms[i])
	}
	return s
}

func (o *okmsSignerVerifier) resolveKeyIDs(ctx context.Context, maxKeys int) ([]uuid.UUID, error) {
	if o.pluginConfig.OnKeyConflict.Strategy == config.ConflictStrategyError {
		id, err := o.keyManager.GetKeyIDByName(ctx, o.keyResourceName)
		if err != nil {
			return nil, err
		}
		return []uuid.UUID{id}, nil
	}

	keys, err := o.keyManager.ListKeysByName(ctx, o.keyResourceName)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("key not found: no key named %s", o.keyResourceName)
	}
	if maxKeys == -1 || maxKeys > len(keys) {
		maxKeys = len(keys)
	}
	return keys[:maxKeys], nil
}

// PublicKey retrieves the public key associated with the keyResourceID.
func (o *okmsSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}

	ids, err := o.resolveKeyIDs(ctx, 1)
	if err != nil {
		return nil, err
	}
	return o.keyManager.GetPublicKey(ctx, ids[0])
}

// SignMessage signs the provided message using the configured key and hash function.
func (o *okmsSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	var digest []byte
	var err error
	var signerOpts crypto.SignerOpts = o.hashFunc
	ctx := context.Background()

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	hashFunc := signerOpts.HashFunc()
	if len(digest) == 0 {
		digest, _, err = signature.ComputeDigestForSigning(message, hashFunc, okmsSupportedHashFuncs, opts...)
		if err != nil {
			return nil, err
		}
	}

	ids, err := o.resolveKeyIDs(ctx, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid key id: %w", err)
	}
	publicKey, err := o.keyManager.GetPublicKey(ctx, ids[0])
	if err != nil {
		return nil, err
	}
	algorithm, err := determineAlgorithm(publicKey, hashFunc, signerOpts)
	if err != nil {
		return nil, err
	}

	return o.keyManager.Sign(ctx, ids[0], digest, algorithm)
}

// VerifySignature verifies a digital signature.
//
// Return nil if the signature is valid, or an error if verification fails.
func (o *okmsSignerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	var digest []byte
	var err error
	var signerOpts crypto.SignerOpts = o.hashFunc
	ctx := context.Background()

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	hashFunc := signerOpts.HashFunc()
	if len(digest) == 0 {
		digest, _, err = signature.ComputeDigestForVerifying(message, hashFunc, okmsSupportedHashFuncs, opts...)
		if err != nil {
			return err
		}
	}

	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	ids, err := o.resolveKeyIDs(ctx, o.pluginConfig.OnKeyConflict.MaxKeysToTry)
	if err != nil {
		return fmt.Errorf("invalid key id: %w", err)
	}

	for _, keyID := range ids {
		publicKey, err := o.keyManager.GetPublicKey(ctx, keyID)
		if err != nil {
			continue
		}
		algorithm, err := determineAlgorithm(publicKey, hashFunc, signerOpts)
		if err != nil {
			continue
		}
		if err := o.keyManager.Verify(ctx, keyID, digest, algorithm, sigBytes); err != nil {
			continue
		}
		return nil
	}
	return fmt.Errorf("failed to verify signature with this key name: %s", o.keyResourceName)
}

// determineAlgorithm determines the digital signature algorithm to use based on the public key type, hash function, and signer options.
func determineAlgorithm(publicKey crypto.PublicKey, hashFunc crypto.Hash, opts crypto.SignerOpts) (types.DigitalSignatureAlgorithms, error) {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return types.ES256, nil
		case elliptic.P384():
			return types.ES384, nil
		case elliptic.P521():
			return types.ES512, nil
		default:
			return "", fmt.Errorf("unsupported elliptic curve: %s", key.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		algorithmPrefix := "RS"
		if _, ok := opts.(*rsa.PSSOptions); ok {
			algorithmPrefix = "PS"
		}
		switch hashFunc {
		case crypto.SHA256:
			return types.DigitalSignatureAlgorithms(algorithmPrefix + "256"), nil
		case crypto.SHA384:
			return types.DigitalSignatureAlgorithms(algorithmPrefix + "384"), nil
		case crypto.SHA512:
			return types.DigitalSignatureAlgorithms(algorithmPrefix + "512"), nil
		default:
			return "", fmt.Errorf("unsupported hash function %v for RSA key", hashFunc)
		}
	default:
		return "", fmt.Errorf("unsupported algorithm")
	}
}

// CreateKey creates a key pair on the KMS and returns the public key.
func (o *okmsSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	keyID, err := o.keyManager.CreateKey(ctx, o.keyResourceName, algorithm)
	if err != nil {
		return nil, err
	}
	o.keyResourceID = keyID.String()

	publicKey, err := o.keyManager.GetPublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

type cryptoSignerWrapper struct {
	ctx      context.Context
	hashFunc crypto.Hash
	sv       *okmsSignerVerifier
	errFunc  func(error)
}

func (c cryptoSignerWrapper) Public() crypto.PublicKey {
	publicKey, err := c.sv.PublicKey(options.WithContext(c.ctx))
	if err != nil && c.errFunc != nil {
		c.errFunc(err)
	}
	return publicKey
}

func (c cryptoSignerWrapper) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := c.hashFunc
	if opts != nil {
		hashFunc = opts.HashFunc()
	}

	okmsOpts := []signature.SignOption{
		options.WithContext(c.ctx),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(hashFunc),
	}

	return c.sv.SignMessage(nil, okmsOpts...)
}

// CryptoSigner returns a crypto.Signer object that uses the underlying SignerVerifier, along with a crypto.SignerOpts object
// that allows the KMS to be used in APIs that only accept the standard golang objects.
func (o *okmsSignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	csw := &cryptoSignerWrapper{
		ctx:      ctx,
		hashFunc: o.hashFunc,
		sv:       o,
		errFunc:  errFunc,
	}

	return csw, o.hashFunc, nil
}
