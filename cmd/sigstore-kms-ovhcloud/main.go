// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/ovh/sigstore-kms-ovhcloud/pkg/config"
	"github.com/ovh/sigstore-kms-ovhcloud/pkg/signing"

	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

const expectedProtocolVersion = "v1"

const usage = `sigstore-kms-ovhcloud is a Sigstore KMS plugin for OVHcloud KMS.

It is not meant to be run directly, but invoked by cosign through the "ovhcloud://<key_id>" KMS URI scheme.

Documentation: https://github.com/ovh/sigstore-kms-ovhcloud#usage
`

func main() {
	if len(os.Args) < 2 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	if protocolVersion := os.Args[1]; protocolVersion != expectedProtocolVersion {
		err := fmt.Errorf("expected protocol version: %s, got %s", expectedProtocolVersion, protocolVersion)
		_ = handler.WriteErrorResponse(os.Stdout, err)
		panic(err)
	}

	pluginArgs, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		_ = handler.WriteErrorResponse(os.Stdout, err)
		panic(err)
	}

	cfg, err := config.NewConfig()
	if err != nil {
		_ = handler.WriteErrorResponse(os.Stdout, err)
		panic(err)
	}

	km, err := signing.NewOkmsKeyManager(cfg)
	if err != nil {
		_ = handler.WriteErrorResponse(os.Stdout, err)
		panic(err)
	}

	signerVerifier := signing.NewOkmsSignerVerifier(km, pluginArgs.InitOptions.KeyResourceID, pluginArgs.InitOptions.HashFunc)
	_, err = handler.Dispatch(os.Stdout, os.Stdin, pluginArgs, signerVerifier)
	if err != nil {
		// Dispatch() will have already called WriteResponse() with the error.
		panic(err)
	}
}
