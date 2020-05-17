#!/usr/bin/env python3
#pylint: disable=multiple-imports
"""Script to disable ACME account"""

import sys, argparse, subprocess, json, base64, binascii, re, copy, logging, requests

LOGGER = logging.getLogger("acme_account_deactivate")
LOGGER.addHandler(logging.StreamHandler())

def account_deactivate(accountkeypath, acme_directory, log=LOGGER):
    def _b64(b):
        """"Encodes string as base64 as specified in ACME RFC """
        return base64.urlsafe_b64encode(b).decode("utf8").rstrip("=")

    def _openssl(command, options, communicate=None):
        """Run openssl command line and raise IOError on non-zero return."""
        openssl = subprocess.Popen(["openssl", command] + options,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out

    def _send_signed_request(url, payload):
        """Sends signed requests to ACME server."""
        nonlocal jws_nonce
        if payload == "": # on POST-as-GET, final payload has to be just empty string
            payload64 = ""
        else:
            payload64 = _b64(json.dumps(payload).encode("utf8"))
        protected = copy.deepcopy(jws_header)
        protected["nonce"] = (jws_nonce
                              or requests.get(acme_config["newNonce"]).headers['Replay-Nonce'])
        protected["url"] = url
        if url == acme_config["newAccount"]:
            del protected["kid"]
        else:
            del protected["jwk"]
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", accountkeypath],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        jose = {
            "protected": protected64, "payload": payload64, "signature": _b64(signature)
        }
        try:
            response = requests.post(url, json=jose, headers=joseheaders)
        except requests.exceptions.RequestException as error:
            response = error.response
        finally:
            jws_nonce = response.headers['Replay-Nonce']
            try:
                return response, response.json()
            except ValueError as error:
                return response, json.dumps({})

    # main code
    adtheaders = {'User-Agent': 'acme-dns-tiny/2.1'}
    joseheaders = copy.deepcopy(adtheaders)
    joseheaders['Content-Type'] = 'application/jose+json'

    log.info("Fetch informations from the ACME directory.")
    directory = requests.get(acme_directory, headers=adtheaders)
    acme_config = directory.json()

    log.info("Parsing account key.")
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
        "kid": None,
    }
    jws_nonce = None

    log.info("Ask CA provider account url.")
    account_request = {}
    account_request["onlyReturnExisting"] = True

    http_response, result = _send_signed_request(acme_config["newAccount"], account_request)
    if http_response.status_code == 200:
        jws_header["kid"] = http_response.headers['Location']
    else:
        raise ValueError("Error looking or account URL: {0} {1}"
                         .format(http_response.status_code, result))

    log.info("Deactivating account...")
    http_response, result = _send_signed_request(jws_header["kid"], {"status": "deactivated"})

    if http_response.status_code == 200:
        log.info("Account key deactivated !")
    else:
        raise ValueError("Error while deactivating the account key: {0} {1}"
                         .format(http_response.status_code, result))

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Tiny ACME client to deactivate ACME account",
        epilog="""This script permanently *deactivates* an ACME account.

You should revoke your certificates *before* using this script,
as the server won't accept any further request with this account.

It will need to access the ACME private account key, so PLEASE READ THROUGH IT!
It's around 150 lines, so it won't take long.

Example: deactivate account.key from staging Let's Encrypt:
  python3 acme_account_deactivate.py \
--account-key account.key \
--acme-directory https://acme-staging-v02.api.letsencrypt.org/directory"""
    )
    parser.add_argument("--account-key", required=True,
                        help="path to the private account key to deactivate")
    parser.add_argument("--acme-directory", required=True,
                        help="ACME directory URL of the ACME server where to remove the key")
    parser.add_argument("--quiet", action="store_const",
                        const=logging.ERROR,
                        help="suppress output except for errors")
    args = parser.parse_args(argv)

    LOGGER.setLevel(args.quiet or logging.INFO)
    account_deactivate(args.account_key, args.acme_directory, log=LOGGER)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
