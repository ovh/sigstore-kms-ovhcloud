#!/bin/bash

set -uo pipefail

echo "E2E Tests"

WORK_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "secret message" > "$WORK_DIR/test.txt"
echo "bad content" > "$WORK_DIR/bad.txt"

require_env() {
    local name="$1"
    if [ -z "${!name:-}" ]; then
        echo "TEST FAILED: $name is not set."
        exit 1
    fi
}

# run_e2e_for_key runs the full public key / sign / verify flow against a single KMS key.
#   $1: label used in logs and file names (e.g. "P-256")
#   $2: KMS key UUID
#   $3: name of the environment variable holding the key UUID (for error messages)
run_e2e_for_key() {
    local label="$1"
    local key_id="$2"
    local env_var="$3"
    local public_key="$WORK_DIR/$label.public.key"
    local bundle="$WORK_DIR/$label.bundle"

    echo "[$label 1/4] Getting public key..."
    if ! cosign public-key --key "ovhcloud://$key_id" > "$public_key"; then
        echo "TEST FAILED ($label): Failed to retrieve public key from KMS ($env_var)."
        exit 1
    fi

    echo "[$label 2/4] Signing..."
    if ! cosign sign-blob --yes --key "ovhcloud://$key_id" --bundle "$bundle" "$WORK_DIR/test.txt"; then
        echo "TEST FAILED ($label): Failed to sign with KMS key."
        exit 1
    fi

    echo "[$label 3/4] Verifying..."
    if ! cosign verify-blob --key "$public_key" --bundle "$bundle" "$WORK_DIR/test.txt"; then
        echo "TEST FAILED ($label): Verification with public key failed."
        exit 1
    fi

    if ! cosign verify-blob --key "ovhcloud://$key_id" --bundle "$bundle" "$WORK_DIR/test.txt"; then
        echo "TEST FAILED ($label): Verification with KMS key failed."
        exit 1
    fi

    echo "[$label 4/4] Verifying that a bad file is rejected..."
    if cosign verify-blob --key "ovhcloud://$key_id" --bundle "$bundle" "$WORK_DIR/bad.txt"; then
        echo "TEST FAILED ($label): Verification of bad file should have failed but succeeded!"
        exit 1
    fi
}

require_env KMS_INTEGRATION_KEYID
require_env KMS_E2E_KEY_P384
require_env KMS_E2E_KEY_P521

run_e2e_for_key "P-256" "$KMS_INTEGRATION_KEYID" "KMS_INTEGRATION_KEYID"
run_e2e_for_key "P-384" "$KMS_E2E_KEY_P384" "KMS_E2E_KEY_P384"
run_e2e_for_key "P-521" "$KMS_E2E_KEY_P521" "KMS_E2E_KEY_P521"

echo "All E2E tests have succeeded"
