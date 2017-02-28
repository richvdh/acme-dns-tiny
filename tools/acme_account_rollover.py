import argparse, subprocess, os, json, base64, binascii, hashlib, re, copy, logging
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

    # helper function to get jws_header from account key path
    def _jws_header(accountkeypath):
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
        return jws_header

    # helper function to sign request with specified key
    def _sign_request(accountkeypath, jwsheader, payload):
        nonlocal jws_nonce
        payload64 = _b64(json.dumps(payload).encode("utf8"))
        protected = copy.deepcopy(jwsheader)
        protected["nonce"] = jws_nonce or urlopen(acme_directory).getheader("Replay-Nonce", None)
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", accountkeypath],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        signedjws = {
            "header": jwsheader, "protected": protected64,
            "payload": payload64, "signature": _b64(signature),
        }
        return signedjws

    # helper function make signed requests
    def _send_signed_request(accountkeypath, jwsheader, url, payload):
        data = json.dumps(_sign_request(accountkeypath, jwsheader, payload))
        try:
            resp = urlopen(url, data.encode("utf8"))
        except HTTPError as httperror:
            resp = httperror
        finally:
            jws_nonce = resp.getheader("Replay-Nonce", None)
            return resp.getcode(), resp.read(), resp.getheaders()

    log.info("Parsing current account key...")
    jws_header = _jws_header(accountkeypath)

    log.info("Parsing new account key...")
    new_jws_header = _jws_header(new_accountkeypath)

    # get ACME server configuration from the directory
    directory = urlopen(acme_directory)
    acme_config = json.loads(directory.read().decode("utf8"))
    jws_nonce = None

    log.info("Register account to get account URL.")
    code, result, headers = _send_signed_request(accountkeypath, jws_header, acme_config["new-reg"], {
        "resource": "new-reg"
    })

    if code not in [201, 409]:
        raise ValueError("Error getting account URL: {0} {1}".format(code,result))
    account_url = dict(headers).get("Location")

    log.info("Rolls over account key...")
    outer_payload = _sign_request(new_accountkeypath, new_jws_header, {
        "url": acme_config["key-change"], # currently needed by boulder implementation in inner payload
        "account": account_url,
        "newKey": new_jws_header["jwk"]})
    outer_payload["resource"] = "key-change" # currently needed by boulder implementation
    code, result, headers = _send_signed_request(accountkeypath, jws_header, acme_config["key-change"], outer_payload)

    if code != 200:
        raise ValueError("Error rolling over account key: {0} {1}".format(code, result))
    log.info("Account keys rolled over !")

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
This script *rolls over* your account key on an ACME server.

It will need to have access to your private account key, so
PLEASE READ THROUGH IT!
It's around 150 lines, so it won't take long.

=== Example Usage ===
Rollover account.keys from account.key to newaccount.key:
python3 acme_account_rollover.py --current account.key --new newaccount.key --acme-directory https://acme-staging.api.letsencrypt.org/directory"""
    )
    parser.add_argument("--current", required = True, help="path to the current private account key")
    parser.add_argument("--new", required = True, help="path to the newer private account key to register")
    parser.add_argument("--acme-directory", required = True, help="ACME directory URL of the ACME server where to remove the key")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    args = parser.parse_args(argv)

    LOGGER.setLevel(args.quiet or LOGGER.level)
    account_rollover(args.current, args.new, args.acme_directory)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
