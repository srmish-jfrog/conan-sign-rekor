""" Plugin to sign/verify Conan packages by using Sigstore's transparency log (Rekor) """

import atexit
import os
import platform
import subprocess
import tempfile
from functools import lru_cache
from shutil import rmtree, which
from tempfile import NamedTemporaryFile

import requests

REKOR_RELEASES_URL = "https://api.github.com/repos/sigstore/rekor/releases/latest"
REKOR_CLI_FILENAME = (
    "rekor-cli.exe" if platform.system().lower() == "windows" else "rekor-cli"
)

CONAN_ROOT_PUBKEY = b"""
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHo3eJf0SHo9kwS8nno872o/vwBvP
YCVI7uS9K4um9vcJUc75+Aiqo76/f/MIWQaPe5d6442bAPB3IKUqH8tviw==
-----END PUBLIC KEY-----
"""


class VerifyException(Exception):
    pass


def _retrieve_rekor_cli() -> str:
    """ Download rekor-cli from GitHub """
    print("Retrieving rekor-cli...")

    # Construct the platform-specific release name
    rekor_cli_asset_filename = (
        f"rekor-cli-{platform.system().lower()}-{platform.machine().lower()}"
    )
    rekor_cli_asset_filename = rekor_cli_asset_filename.replace("x86_64", "amd64")
    if platform.system().lower() == "windows":
        rekor_cli_asset_filename += ".exe"

    # Get the release URL
    headers = {"Accept": "application/vnd.github+json"}
    try:
        resp = requests.get(REKOR_RELEASES_URL, headers=headers).json()
    except Exception:
        raise Exception("Failed getting latest Rekor release URL")
    for asset in resp["assets"]:
        if asset["name"] == rekor_cli_asset_filename:
            break
    else:
        raise Exception("Error parsing GitHub release JSON")

    # Download the binary
    with open(REKOR_CLI_FILENAME, "wb") as f:
        resp = requests.get(asset["browser_download_url"])
        f.write(resp.content)
    return os.path.realpath(REKOR_CLI_FILENAME)


@lru_cache(maxsize=10)
def _find_rekor_cli() -> str:
    """ Get path to the rekor CLI executable """
    # Check direct envvar
    rekor_cli_path = os.getenv("CONANSIGN_REKOR_CLI_PATH")
    if rekor_cli_path:
        return rekor_cli_path

    # Check PATH
    rekor_cli_path = which(REKOR_CLI_FILENAME)
    if rekor_cli_path:
        return rekor_cli_path

    # Check current dir (perhaps auto-fetched in previous run)
    if REKOR_CLI_FILENAME in os.listdir("."):
        return os.path.realpath(os.path.join(".", REKOR_CLI_FILENAME))

    # Retrieve from GitHub (if allowed)
    if os.getenv("CONANSIGN_REKOR_CLI_AUTODOWNLOAD"):
        rekor_cli_path = _retrieve_rekor_cli()
        if rekor_cli_path:
            return rekor_cli_path

    # Couldn't find rekor-cli!
    excmsg = "Missing rekor-cli!\n"
    excmsg += "Either set CONANSIGN_REKOR_CLI_AUTODOWNLOAD=1 to allow auto-fetching the rekor-cli executable\n"
    excmsg += "or set CONANSIGN_REKOR_CLI_PATH=/path/to/rekor-cli"
    raise Exception(excmsg)


def _should_sign() -> bool:
    return bool(os.getenv("CONANSIGN_REKOR_PRIVKEY"))


def _get_conan_root_pubkey() -> str:
    tmpfile = NamedTemporaryFile(delete=False)
    tmpfile.write(CONAN_ROOT_PUBKEY)
    atexit.register(os.unlink, tmpfile.name)  # cleanup tmpfile on exit
    return tmpfile.name


def sign(_, artifacts_folder: str, signature_folder: str):
    # Should we sign?
    if not _should_sign():
        return
    privkey_filepath = os.getenv("CONANSIGN_REKOR_PRIVKEY")
    if not privkey_filepath:
        raise Exception("Missing envvar CONANSIGN_REKOR_PRIVKEY")
    pubkey_filepath = os.getenv("CONANSIGN_REKOR_PUBKEY")
    if not pubkey_filepath:
        raise Exception("Missing envvar CONANSIGN_REKOR_PUBKEY")

    # Find dependencies
    rekor_cli_path = _find_rekor_cli()
    if not which("openssl"):
        raise Exception("Missing openssl binary")

    # Sign & upload each artifact using X509
    print(
        f"Signing artifacts from {artifacts_folder} to {signature_folder}, using private key {privkey_filepath}"
    )
    for fname in os.listdir(artifacts_folder):
        in_fpath = os.path.join(artifacts_folder, fname)
        out_fpath = os.path.join(signature_folder, fname + ".sig")
        if os.path.isfile(in_fpath):
            # Sign
            openssl_sign_cmd = [
                "openssl",
                "dgst",
                "-sha256",
                "-sign", privkey_filepath,
                "-out", out_fpath,
                in_fpath,
            ]
            subprocess.check_call(openssl_sign_cmd, stdout=subprocess.DEVNULL)

            # Upload to Rekor
            rekor_upload_cmd = [
                rekor_cli_path,
                "upload",
                "--pki-format", "x509",
                "--signature", out_fpath,
                "--public-key", pubkey_filepath,
                "--artifact", in_fpath,
            ]
            subprocess.check_call(rekor_upload_cmd, stdout=subprocess.DEVNULL)


def verify(_, artifacts_folder: str, signature_folder: str):
    # Should we verify? (verification enabled when NOT signing)
    if _should_sign():
        return
    pubkey_filepath = os.getenv("CONANSIGN_REKOR_PUBKEY", _get_conan_root_pubkey())

    # Find dependencies
    rekor_cli_path = _find_rekor_cli()

    # Verify each artifact using X509
    print(
        f"Verifying artifacts from {artifacts_folder} with {signature_folder}, using public key {pubkey_filepath}"
    )
    for fname in os.listdir(artifacts_folder):
        artifact_fpath = os.path.join(artifacts_folder, fname)
        sig_fpath = os.path.join(signature_folder, fname + ".sig")
        if os.path.isfile(artifact_fpath):
            if not os.path.isfile(sig_fpath):
                raise VerifyException(
                    f"Missing signature file for artifact {artifact_fpath}"
                )

            # Verify against Rekor
            rekor_upload_cmd = [
                rekor_cli_path,
                "verify",
                "--pki-format", "x509",
                "--signature", sig_fpath,
                "--public-key", pubkey_filepath,
                "--artifact", artifact_fpath,
            ]
            try:
                subprocess.check_call(rekor_upload_cmd, stdout=subprocess.DEVNULL)
            except Exception as exc:
                raise VerifyException(f"Rekor verification failed with error: {exc}")


def _test_main():
    """ Standalone tester function """
    if not which("openssl"):
        raise Exception("Missing openssl binary")

    # Create temp workdirs
    artifacts_folder = tempfile.mkdtemp()
    signature_folder = tempfile.mkdtemp()
    try:
        # Create an artifact to sign
        artifact_path = os.path.join(artifacts_folder, "artifact.bin")
        with open(artifact_path, "wb") as f:
            f.write(os.urandom(100))

        # Create a signing keypair
        privkey_path = os.path.join(signature_folder, "ec_private.pem")
        pubkey_path = os.path.join(signature_folder, "ec_public.pem")
        subprocess.check_call(
            f"openssl ecparam -genkey -name prime256v1 > {privkey_path}",
            shell=True,
            stderr=subprocess.DEVNULL,
        )
        subprocess.check_call(
            f"openssl ec -in {privkey_path} -pubout > {pubkey_path}",
            shell=True,
            stderr=subprocess.DEVNULL,
        )

        # Set envvars for signing
        os.environ["CONANSIGN_REKOR_PRIVKEY"] = privkey_path
        os.environ["CONANSIGN_REKOR_PUBKEY"] = pubkey_path

        # Sign
        print("Test signing...")
        sign(None, artifacts_folder, signature_folder)

        # Set envvars for verification
        del os.environ["CONANSIGN_REKOR_PRIVKEY"]

        # Verify (assert success)
        print("Test verification (expect success)...")
        verify(None, artifacts_folder, signature_folder)

        # Modify artifact
        with open(artifact_path, "wb") as f:
            f.write(os.urandom(100))

        # Verify (assert failure)
        try:
            print("Test verification (expect failure)...")
            verify(None, artifacts_folder, signature_folder)
            # If we got here - verification unexpectedly succeeded (didn't throw an exception)
            raise Exception("Artifact verification should have failed!")
        except VerifyException:
            pass

        print("Plugin test successful")
    finally:
        # Cleanup
        rmtree(artifacts_folder)
        rmtree(signature_folder)


if __name__ == "__main__":
    _test_main()
