# Conan Rekor/Sigstore signature plugin


## Dependencies

The `rekor-cli` executable must be available in the user's `PATH` .

`rekor-cli` can be automatically downloaded by the plugin, by specifying the environment variable `CONANSIGN_REKOR_CLI_AUTODOWNLOAD=1`. Alternatively, an arbitrary path to `rekor-cli` can be set by using `CONANSIGN_REKOR_CLI_PATH`.

If package signing is enabled (`CONANSIGN_REKOR_PRIVKEY` is set), then the `openssl` executable must also be available in the user's `PATH`.



## Installation

```shell
pip install -r requirements.txt
mkdir ~/.conan2/extensions/plugins/sign
cp conan-sign-rekor.py ~/.conan2/extensions/plugins/sign/sign.py
```



## Usage

By default, the plugin will verify downloaded Conan packages against Sigstore by using the Conan root X.509 public key.

The plugin can be made to sign or verify packages using any X.509 keypair, by setting the appropriate environment variables

### Environment variables

All environment variables are optional -

* `CONANSIGN_REKOR_CLI_PATH` - Can be set to the path of the `rekor-cli` binary, in case it's not available in the user's `PATH`.
* `CONANSIGN_REKOR_CLI_AUTODOWNLOAD` - When set, allows `rekor-cli` to be fetched automatically from GitHub.
* `CONANSIGN_REKOR_PUBKEY` - Path to an X.509 public key file for package verification. By default, uses the Conan root X.509 public key.
* `CONANSIGN_REKOR_PRIVKEY` - Path to an X.509 private key file for package signing. By default, no signing will take place. If set, then `CONANSIGN_REKOR_PUBKEY` must also be set explicitly. When signing, verification is disabled.

### Examples

<u>Signing with user key</u>

`CONANSIGN_REKOR_PRIVKEY=ec_private.pem CONANSIGN_REKOR_PUBKEY=ec_public.pem conan upload  mypackage/1.0`



<u>Verification with user key</u>

`CONANSIGN_REKOR_PUBKEY=ec_public.pem conan install .`



<u>Verification with Conan root key (default)</u>

`conan install .`



<u>Disable verification</u>

`CONANSIGN_REKOR_PRIVKEY=dummy conan install .`



## Generating a compatible keypair

```shell
$ openssl ecparam -genkey -name prime256v1 > ec_private.pem
$ openssl ec -in ec_private.pem -pubout > ec_public.pem
```