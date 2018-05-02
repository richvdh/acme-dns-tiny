#!/usr/bin/env python3
import sys, argparse, subprocess, json, base64, binascii, re, copy, logging, requests

LOGGER = logging.getLogger("acme_account_rollover")
LOGGER.addHandler(logging.StreamHandler())

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
            r"modulus:\r?\n\s+00:([a-f0-9\:\s]+?)\r?\npublicExponent: ([0-9]+)",
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
            "kid": None
        }
        return jws_header

    # helper function to sign request with specified key path
    def _sign_request(url, keypath, payload):
        nonlocal jws_nonce
        payload64 = _b64(json.dumps(payload).encode("utf8"))
        if keypath == accountkeypath:
            protected = copy.deepcopy(jws_header)
            protected["nonce"] = jws_nonce or requests.get(acme_config["newNonce"]).headers['Replay-Nonce']
        elif keypath == new_accountkeypath:
            protected = copy.deepcopy(new_jws_header)
        if (keypath == new_accountkeypath
            or url == acme_config["newAccount"]):
            del protected["kid"]
        else:
            del protected["jwk"]
        protected["url"] = url
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", keypath],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        signedjws = {
            "protected": protected64, "payload": payload64,"signature": _b64(signature)
        }
        return signedjws

    # helper function make signed requests
    def _send_signed_request(url, keypath, payload):
        nonlocal jws_nonce
        jws = _sign_request(url, keypath, payload)
        try:
            resp = requests.post(url, json=jws, headers=joseheaders)
        except requests.exceptions.RequestException as error:
            resp = error.response
        finally:
            jws_nonce = resp.headers['Replay-Nonce']
            if resp.text != '':
                return resp.status_code, resp.json(), resp.headers
            else:
                return resp.status_code, json.dumps({}), resp.headers

    # main code
    adtheaders =  {'User-Agent': 'acme-dns-tiny/2.0'}
    joseheaders=copy.deepcopy(adtheaders)
    joseheaders['Content-Type']='application/jose+json'

    log.info("Fetch informations from the ACME directory.")
    directory = requests.get(acme_directory, headers=adtheaders)
    acme_config = directory.json()

    log.info("Parsing current account key...")
    jws_header = _jws_header(accountkeypath)

    log.info("Parsing new account key...")
    new_jws_header = _jws_header(new_accountkeypath)

    jws_nonce = None

    log.info("Ask CA provider account url.")
    code, result, headers = _send_signed_request(acme_config["newAccount"], accountkeypath, {
        "onlyReturnExisting": True })
    if code == 200:
        jws_header["kid"] = headers["Location"]
    else:
        raise ValueError("Error looking or account URL: {0} {1}".format(code, result))

    log.info("Rolls over account key...")
    outer_payload = _sign_request(jws_header["kid"], new_accountkeypath, {
        "account": jws_header["kid"],
        "newKey": new_jws_header["jwk"] })
    code, result, headers = _send_signed_request(jws_header["kid"], accountkeypath, outer_payload)

    if code != 200:
        raise ValueError("Error rolling over account key: {0} {1}".format(code, result))
    log.info("Account keys rolled over !")

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Tiny ACME client to roll over an ACME account key with another one.",
        epilog="""This script *rolls over* ACME account keys.

It will need to have access to the ACME private account keys, so PLEASE READ THROUGH IT!
It's around 150 lines, so it won't take long.

Example: roll over account key from account.key to newaccount.key:
  python3 acme_account_rollover.py --current account.key --new newaccount.key --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory""")
    parser.add_argument("--current", required = True, help="path to the current private account key")
    parser.add_argument("--new", required = True, help="path to the newer private account key to register")
    parser.add_argument("--acme-directory", required = True, help="ACME directory URL of the ACME server where to remove the key")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    args = parser.parse_args(argv)

    LOGGER.setLevel(args.quiet or logging.INFO)
    account_rollover(args.current, args.new, args.acme_directory, log=LOGGER)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
