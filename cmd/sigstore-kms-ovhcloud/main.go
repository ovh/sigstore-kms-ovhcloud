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

func main() {
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
