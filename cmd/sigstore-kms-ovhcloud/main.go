package main

import (
	"fmt"
	"os"
	"sigstore-kms-ovhcloud/pkg/signing"

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

	signerVerifier := &signing.OkmsSignerVerifier{
		HashFunc:      pluginArgs.InitOptions.HashFunc,
		KeyResourceID: pluginArgs.InitOptions.KeyResourceID,
	}

	_, err = handler.Dispatch(os.Stdout, os.Stdin, pluginArgs, signerVerifier)
	if err != nil {
		// Dispatch() will have already called WriteResponse() with the error.
		panic(err)
	}
}
