import os, sys, configparser
from tempfile import NamedTemporaryFile
from subprocess import Popen
from urllib.request import urlopen

# domain with server.py running on it for testing
DOMAIN = os.getenv("GITLABCI_DOMAIN")
CAURL = os.getenv("GITLABCI_CAURL", "https://acme-staging.api.letsencrypt.org")
CHALLENGEDELAY = os.getenv("GITLABCI_CHALLENGDELAY", "3")
DNSHOST = os.getenv("GITLABCI_DNSHOST")
DNSZONE = os.getenv("GITLABCI_DNSZONE")
DNSPORT = os.getenv("GITLABCI_DNSPORT", "53")
TSIGKEYNAME = os.getenv("GITLABCI_TSIGKEYNAME")
TSIGKEYVALUE = os.getenv("GITLABCI_TSIGKEYVALUE")
TSIGALGORITHM = os.getenv("GITLABCI_TSIGALGORITHM")

# generate account and domain keys
def gen_configs():
    # good account key
    account_key = NamedTemporaryFile()
    Popen(["openssl", "genrsa", "-out", account_key.name, "2048"]).wait()

    # weak 1024 bit key
    weak_key = NamedTemporaryFile()
    Popen(["openssl", "genrsa", "-out", weak_key.name, "1024"]).wait()

    # good domain key
    domain_key = NamedTemporaryFile()
    domain_csr = NamedTemporaryFile()
    Popen(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", domain_key.name,
        "-subj", "/CN={0}".format(DOMAIN), "-out", domain_csr.name]).wait()

    # subject alt-name domain
    san_csr = NamedTemporaryFile()
    san_conf = NamedTemporaryFile()
    san_conf.write(open("/etc/ssl/openssl.cnf").read().encode("utf8"))
    san_conf.write("\n[SAN]\nsubjectAltName=DNS:{0},DNS:www.{0}\n".format(DOMAIN).encode("utf8"))
    san_conf.seek(0)
    Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key.name,
        "-subj", "/", "-reqexts", "SAN", "-config", san_conf.name,
        "-out", san_csr.name]).wait()

    # invalid domain csr
    invalid_csr = NamedTemporaryFile()
#     Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key.name,
#         "-subj", "/CN=\xC3\xA0\xC2\xB2\xC2\xA0_\xC3\xA0\xC2\xB2\xC2\xA0.com", "-out", invalid_csr.name]).wait()

    # nonexistent domain csr
    nonexistent_csr = NamedTemporaryFile()
    Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key.name,
        "-subj", "/CN=404.{0}".format(DOMAIN), "-out", nonexistent_csr.name]).wait()

    # account-signed domain csr
    account_csr = NamedTemporaryFile()
    Popen(["openssl", "req", "-new", "-sha256", "-key", account_key.name,
        "-subj", "/CN={0}".format(DOMAIN), "-out", account_csr.name]).wait()
    
    # Default test configuration
    config = configparser.ConfigParser()
    config.read("./example.ini".format(DOMAIN))
    config["acmednstiny"]["CAUrl"] = CAURL
    config["acmednstiny"]["CheckChallengeDelay"] = CHALLENGEDELAY
    config["TSIGKeyring"]["KeyName"] = TSIGKEYNAME
    config["TSIGKeyring"]["KeyValue"] = TSIGKEYVALUE
    config["TSIGKeyring"]["Algorithm"] = TSIGALGORITHM
    config["DNS"]["Host"] = DNSHOST
    config["DNS"]["Port"] = DNSPORT
    config["DNS"]["Zone"] = DNSZONE
    
    goodCName = NamedTemporaryFile()
    config["acmednstiny"]["AccountKeyFile"] = account_key.name
    config["acmednstiny"]["CSRFile"] = domain_csr.name
    with open(goodCName.name, 'w') as configfile:
        config.write(configfile)
    
    goodSAN = NamedTemporaryFile()
    config["acmednstiny"]["AccountKeyFile"] = account_key.name
    config["acmednstiny"]["CSRFile"] = san_csr.name
    with open(goodSAN.name, 'w') as configfile:
        config.write(configfile)
    
    weakKey = NamedTemporaryFile()
    config["acmednstiny"]["AccountKeyFile"] = weak_key.name
    config["acmednstiny"]["CSRFile"] = domain_csr.name
    with open(weakKey.name, 'w') as configfile:
        config.write(configfile)
    
    invalidCSR = NamedTemporaryFile()
    config["acmednstiny"]["AccountKeyFile"] = account_key.name
    config["acmednstiny"]["CSRFile"] = invalid_csr.name
    with open(invalidCSR.name, 'w') as configfile:
        config.write(configfile)
        
    inexistantDomain = NamedTemporaryFile()
    config["acmednstiny"]["AccountKeyFile"] = account_key.name
    config["acmednstiny"]["CSRFile"] = nonexistent_csr.name
    with open(inexistantDomain.name, 'w') as configfile:
        config.write(configfile)
        
    accountAsDomain = NamedTemporaryFile()
    config["acmednstiny"]["AccountKeyFile"] = account_key.name
    config["acmednstiny"]["CSRFile"] = account_csr.name
    with open(accountAsDomain.name, 'w') as configfile:
        config.write(configfile)

    return {
        "goodCName": goodCName,
        "goodSAN": goodSAN,
        "weakKey": weakKey,
        "invalidCSR": invalidCSR,
        "inexistantDomain": inexistantDomain,
        "accountAsDomain": accountAsDomain,
        "key": {"accountkey": account_key,
                 "weakkey": weak_key,
                 "domainkey": domain_key},
        "csr" : {"domaincsr": domain_csr,
                 "sancsr": san_csr,
                 "invalidcsr": invalid_csr,
                 "nonexistantcsr": nonexistent_csr,
                 "accountcsr": account_csr}
    }

