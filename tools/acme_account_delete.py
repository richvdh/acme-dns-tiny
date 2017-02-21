import argparse, subprocess, json, base64, binascii, re, copy, logging
from urllib.request import urlopen
from urllib.error import HTTPError

LOGGER = logging.getLogger("acme_account_delete")
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def delete_account(accountkeypath, acme_directory, log=LOGGER):
    # helper function base64 encode as defined in acme spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode("utf8").rstrip("=")

    # helper function to run openssl command
    def _openssl(command, options, communicate=None):
        openssl = subprocess.Popen(["openssl", command] + options,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out

    # helper function make signed requests
    def _send_signed_request(url, payload):
        nonlocal jws_nonce
        payload64 = _b64(json.dumps(payload).encode("utf8"))
        protected = copy.deepcopy(header)
        protected["nonce"] = jws_nonce or urlopen(acme_directory).getheader("Replay-Nonce", None)
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", accountkeypath],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": _b64(signature),
        })
        try:
            resp = urlopen(url, data.encode("utf8"))
        except HTTPError as httperror:
            resp = httperror
        finally:
            jws_nonce = resp.getheader("Replay-Nonce", None)
            return resp.getcode(), resp.read(), resp.getheaders()

    # parse account key to get public key
    log.info("Parsing account key...")
    accountkey = _openssl("rsa", ["-in", accountkeypath, "-noout", "-text"])
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        accountkey.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    
    # get ACME server configuration from the directory
    directory = urlopen(acme_directory)
    acme_config = json.loads(directory.read().decode("utf8"))
    jws_nonce = None
    
    log.info("Register account to get account URL.") 
    code, result, headers = _send_signed_request(acme_config["new-reg"], {
        "resource": "new-reg"
    })

    if code == 201:
        account_url = dict(headers).get("Location")
        log.info("Registered! (account: '{0}')".format(account_url))
    elif code == 409:
        account_url = dict(headers).get("Location")
        log.info("Already registered! (account: '{0}')".format(account_url))

    log.info("Delete account...")
    code, result, headers = _send_signed_request(account_url, {
        "resource": "reg",
        "delete": True,
    })

    if code not in [200,202]:
        raise ValueError("Error deleting account key: {0} {1}".format(code, result))
    log.info("Account key deleted !")

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script *deletes* your account from an ACME server.

            It will need to have access to your private account key, so
            PLEASE READ THROUGH IT!
            It's around 150 lines, so it won't take long.

            === Example Usage ===
            Remove account.key from staging Let's Encrypt:
            python3 acme_account_delete.py --account-key account.key --acme-directory https://acme-staging.api.letsencrypt.org/directory
            """)
    )
    parser.add_argument("--account-key", required = True, help="path to the private account key to delete")
    parser.add_argument("--acme-directory", required = True, help="ACME directory URL of the ACME server where to remove the key")
    parser.add_argument("--quiet", action="store_const",
                        const=logging.ERROR,
                        help="suppress output except for errors")
    args = parser.parse_args(argv)

    LOGGER.setLevel(args.quiet or LOGGER.level)
    account_delete(args.account_key, args.acme_directory)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
