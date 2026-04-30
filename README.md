# sigstore-kms-ovhcloud

[![Cosign Compatibility](https://img.shields.io/badge/cosign%20compatibility-v3.0.5-blue?logo=linux-foundation)](https://github.com/sigstore/cosign/releases/tag/v3.0.5)

[Sigstore](https://sigstore.dev) KMS plugin
for [OVHcloud KMS](https://help.ovhcloud.com/csm/en-ie-kms-quick-start?id=kb_article_view&sysparm_article=KB0063362).

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Related links](#related-links)

## Installation

To permit sigstore to use the plugin, the binary must be in your system's PATH.<br>

To build and install the plugin, you can use this command:

```bash
make install PREFIX=<PREFIX>
```

By default, `PREFIX` is set to `/usr/local`, so the binary will be located in `/usr/local/bin/sigstore-kms-ovhcloud`.

## Configuration

Default settings can be set using a configuration file named `okms.yaml` and located in the `${HOME}/.ovh-kms`
directory.
If you don't wish to use this default file, you can create your own and specify the full path in the `KMS_CONFIG`
environment variable.

Example for `okms.yaml`:

```yaml
version: 1
profile: default # Name of the active profile
profiles:
  default:
    restapi:
      endpoint: https://myserver.acme.com
      ca: /path/to/public-ca.crt # Optional if the CA is in system store
      auth:
        type: mtls # Optional, default to "mtls"
        cert: /path/to/domain/cert.pem
        key: /path/to/domain/key.pem

  token-profile:
    restapi:
      endpoint: https://myserver.acme.com
      ca: /path/to/public-ca.crt # Optional if the CA is in system store
      auth:
        type: token
        token: token
        okmsId: okms_id
```

These settings can be overwritten using environment variables:

- `KMS_RESTAPI_ENDPOINT`
- `KMS_RESTAPI_CA`
- `KMS_RESTAPI_TYPE`
- `KMS_RESTAPI_CERT`
- `KMS_RESTAPI_KEY`
- `KMS_RESTAPI_OKMSID`
- `KMS_RESTAPI_TOKEN`

## Usage

The plugin uses the `ovhcloud://` URI scheme followed by the specific key UUID you want to use for cryptographic
operations.

URI format : `ovhcloud://<key_uuid>`

### Generating a key pair

```bash
cosign generate-key-pair --kms ovhcloud://<key_name>
```

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
