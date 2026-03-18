# sigstore-kms-ovhcloudkms

[Sigstore](https://sigstore.dev) KMS plugin
for [OVHcloud KMS](https://help.ovhcloud.com/csm/en-ie-kms-quick-start?id=kb_article_view&sysparm_article=KB0063362).

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)

## Installation

To permit sigstore to use the plugin, the binary must be in your system's PATH.<br>

To build and install the plugin, you can use this command:

```bash
make install PREFIX=<PREFIX>
```

By default, `PREFIX` is set to `/usr/local`, so the binary will be located in `/usr/local/bin/sigstore-kms-ovhcloudkms`.

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
    http:
      id: okms_id
      endpoint: https://myserver.acme.com
      ca: /path/to/public-ca.crt # Optional if the CA is in system store
      auth:
        cert: /path/to/domain/cert.pem
        key: /path/to/domain/key.pem
```

These settings can be overwritten using environment variables:

- `KMS_HTTP_ID`
- `KMS_HTTP_ENDPOINT`
- `KMS_HTTP_CA`
- `KMS_HTTP_CERT`
- `KMS_HTTP_KEY`

## Usage

Coming soon...
