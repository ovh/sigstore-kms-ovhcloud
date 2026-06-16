#!/bin/bash

set -uo pipefail

echo "E2E Tests"

cleanup() {
    rm -f test.txt test.bundle public.key bad.txt
}
trap cleanup EXIT

echo "secret message" > test.txt

echo "[1/3] Getting public key..."
if ! cosign public-key --key ovhcloud://"$KMS_INTEGRATION_KEYID" > public.key; then
  echo "TEST FAILED: Failed to retrieve public key from KMS."
  exit 1
fi


echo "[2/3] Signing..."
if ! cosign sign-blob --key ovhcloud://"$KMS_INTEGRATION_KEYID" --bundle test.bundle test.txt; then
  echo "TEST FAILED: Failed to sign with KMS key."
  exit 1
fi


echo "[3/3] Verifying..."
if ! cosign verify-blob --key public.key --bundle test.bundle test.txt; then
    echo "TEST FAILED: Verification with public key failed."
    exit 1
fi

if ! cosign verify-blob --key ovhcloud://"$KMS_INTEGRATION_KEYID" --bundle test.bundle test.txt; then
    echo "TEST FAILED: Verification with KMS key failed."
    exit 1
fi

echo "bad content" > bad.txt
if cosign verify-blob --key ovhcloud://"$KMS_INTEGRATION_KEYID" --bundle test.bundle bad.txt; then
    echo "TEST FAILED: Verification of bad file should have failed but succeeded!"
    exit 1
fi

echo "All E2E tests have succeeded"
