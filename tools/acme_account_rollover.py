import argparse, subprocess, os, json, base64, binascii, re, copy, logging
from urllib.request import urlopen
from urllib.error import HTTPError

LOGGER = logging.getLogger("acme_account_rollover")
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def account_rollover(accountkeypath, new_accountkeypath, acme_directory, log=LOGGER):
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

    # helper function to sign request with specified key
    def _sign_request(accountkeypath, jwsheader, protected, payload):
        nonlocal jws_nonce
        payload64 = _b64(json.dumps(payload).encode("utf8"))
        protected["nonce"] = jws_nonce or urlopen(acme_directory).getheader("Replay-Nonce", None)
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", accountkeypath],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        signedjws = json.dumps({
            "header": jwsheader, "protected": protected64,
            "payload": payload64, "signature": _b64(signature),
        })
        return signedjws

    # helper function make signed requests
    def _send_signed_request(accountkeypath, jwsheader, protected, url, payload):
        data = _sign_request(accountkeypath, jwsheader, protected, payload)
        try:
            resp = urlopen(url, data.encode("utf8"))
        except HTTPError as httperror:
            resp = httperror
        finally:
            jws_nonce = resp.getheader("Replay-Nonce", None)
            return resp.getcode(), resp.read(), resp.getheaders()

    log.info("Parsing current account key...")
    accountkey = _openssl("rsa", ["-in", accountkeypath, "-noout", "-text"])
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        accountkey.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    jws_header = {
        "alg": "RS256",
        "jwk": {
            "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    accountkey_json = json.dumps(jws_header["jwk"], sort_keys=True, separators=(",", ":"))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())
    
    log.info("Parsing new account key...")
    newaccountkey = _openssl("rsa", ["-in", new_accountkeypath, "-noout", "-text"])
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        accountkey.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    new_jws_header = {
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
    code, result, headers = _send_signed_request(accountkeypath, jws_header, acme_config["new-reg"], {
        "resource": "new-reg"
    })

    if code not in [201, 409]
        raise ValueError("Error getting account URL: {0} {1}".format(code,result)
    account_url = dict(headers).get("Location")

    log.info("Rolls over account key...")
    code, result, headers = _send_signed_request(new_accountkeypath, new_jws_header, acme_config["key-change"], {
        "resource": "key-change",
        _sign_request(new_accountkeypath, new_jws_header, {
                        "url": acme_config["key-change"],
                        "account": account_url,
                        "newKey": _b64(thumbprint)})
    })

    if code != 200:
        raise ValueError("Error rolling over account key: {0} {1}".format(code, result))
    log.info("Account keys rolled over !")

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script *rolls over* your account key on an ACME server.

            It will need to have access to your private account key, so
            PLEASE READ THROUGH IT!
            It's around 150 lines, so it won't take long.

            === Example Usage ===
            Remove account.key from staging Let's Encrypt:
            python3 acme_account_delete.py --current-account-key account.key --new-account-key newaccount.key --acme-directory https://acme-staging.api.letsencrypt.org/directory
            """)
    )
    parser.add_argument("--current-account-key", required = True, help="path to the current private account key")
    parser.add_argument("--new-account-key", required = True, help="path to the newer private account key to register")
    parser.add_argument("--acme-directory", required = True, help="ACME directory URL of the ACME server where to remove the key")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    args = parser.parse_args(argv)

    LOGGER.setLevel(args.quiet or LOGGER.level)
    account_rollover(args.current_account_key, args.new_account_key, args.acme_directory)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
