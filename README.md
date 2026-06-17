# sigstore-kms-ovhcloud

[![build-and-test](https://github.com/ovh/sigstore-kms-ovhcloud/actions/workflows/build_and_test.yaml/badge.svg)](https://github.com/ovh/sigstore-kms-ovhcloud/actions/workflows/build_and_test.yaml)
[![Cosign Compatibility](https://img.shields.io/badge/cosign%20compatibility-v3.0.6-blue?logo=linux-foundation)](https://github.com/sigstore/cosign/releases/tag/v3.0.6)

[Sigstore](https://sigstore.dev) KMS plugin
for [OVHcloud KMS](https://help.ovhcloud.com/csm/en-ie-kms-quick-start?id=kb_article_view&sysparm_article=KB0063362).

## Table of Contents

- [Installation](#installation)
  - [Installation command](#installation-command)
  - [Binary download](#binary-download)
  - [Install from the source](#install-from-the-source)
- [Configuration](#configuration)
  - [mTLS authentication](#mtls-authentication)
  - [Token authentication](#token-authentication)
- [Usage](#usage)
- [Related links](#related-links)

## Installation

To permit sigstore to use the plugin, the binary must be in your system's PATH.<br>

### Installation command

```sh
curl -fsSL https://raw.githubusercontent.com/ovh/sigstore-kms-ovhcloud/main/install.sh | sh
```

The binary is installed in `$HOME/.local/bin` by default (created if it does not exist).
Make sure this directory is in your `PATH`.

**Install a specific version**:

```sh
curl -fsSL https://raw.githubusercontent.com/ovh/sigstore-kms-ovhcloud/main/install.sh | sh -s <version>
```

**Custom installation directory**:

```sh
curl -fsSL https://raw.githubusercontent.com/ovh/sigstore-kms-ovhcloud/main/install.sh | sh -s -- -b <path>
```

### Binary download

1. Download [latest release](https://github.com/ovh/sigstore-kms-ovhcloud/releases/latest)
2. Untar / unzip the archive
3. Add the containing folder to your `PATH` environment variable, or move the binary into a directory that is already in your `PATH`

### Install from the source

Requires Go to be installed on your system.

**Using `go install`**:

```sh
go install github.com/ovh/sigstore-kms-ovhcloud/cmd/sigstore-kms-ovhcloud@latest
```

**Using `make`**:

```sh
git clone https://github.com/ovh/sigstore-kms-ovhcloud.git
cd sigstore-kms-ovhcloud
make install # installs to /usr/local/bin by default
# or:
make install PREFIX=$HOME/.local # installs to $HOME/.local/bin
```

## Configuration

**OVH provider supports both `mTLS` and `token` authentication.**

Default settings can be set using a configuration file named `okms.yaml` and located in the `${HOME}/.ovh-kms`
directory.
If you don't wish to use this default file, you can create your own and specify the full path in the `KMS_CONFIG`
environment variable.

### mTLS authentication

Example of `okms.yaml`:

```yaml
version: 1
profile: default # Name of the active profile
profiles:
  default:
    restapi:
      endpoint: <kms-endpoint> # for example: "https://eu-west-rbx.okms.ovh.net"
      ca: /path/to/public-ca.crt # Optional if the CA is in system store
      auth:
        cert: /path/to/domain/cert.pem
        key: /path/to/domain/key.pem
```

These settings can be overwritten using environment variables:

- `KMS_RESTAPI_ENDPOINT`
- `KMS_RESTAPI_CA`
- `KMS_RESTAPI_CERT`
- `KMS_RESTAPI_KEY`

### Token authentication

Example of `okms.yaml`:

```yaml
version: 1
profile: default # Name of the active profile
profiles:
  default:
    restapi:
      endpoint: <kms-endpoint> # for example: "https://eu-west-rbx.okms.ovh.net"
      ca: /path/to/public-ca.crt # Optional if the CA is in system store
      auth:
        type: token
        token: <token>
        okmsId: <okms-id> # for example: "734b9b45-8b1a-469c-b140-b10bd6540017"
```

These settings can be overwritten using environment variables:

- `KMS_RESTAPI_ENDPOINT`
- `KMS_RESTAPI_CA`
- `KMS_RESTAPI_TYPE`
- `KMS_RESTAPI_OKMSID`
- `KMS_RESTAPI_TOKEN`

## Usage

The plugin uses the `ovhcloud://` URI scheme followed by the specific key UUID you want to use for cryptographic
operations.

URI format : `ovhcloud://<key_id>`

The `<key_id>` is a UUID, for example: `f47ac10b-58cc-4372-a567-0e02b2c3d479`. You can generate one using `uuidgen`:

```bash
uuidgen
```

### Generating a key pair

```bash
cosign generate-key-pair --kms ovhcloud://<key_id>
```

The generated key will have the name: `cosign-<unix_ms_utc>`.

### Extracting the public key

```bash
cosign public-key --key ovhcloud://<key_id>
```

### Docker image

#### Signing

```bash
cosign sign --key ovhcloud://<key_id> <my_image>@<image_digest>
```

#### Verifying

```bash
cosign verify --key ovhcloud://<key_id> <my_image>@<image_digest>
```

## Related links

* Contribute: https://github.com/ovh/sigstore-kms-ovhcloud/blob/master/CONTRIBUTING.md
* Report bugs: https://github.com/ovh/sigstore-kms-ovhcloud/issues
