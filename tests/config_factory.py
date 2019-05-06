import os, configparser
from tempfile import NamedTemporaryFile
from subprocess import Popen

# domain with server.py running on it for testing
DOMAIN = os.getenv("GITLABCI_DOMAIN")
ACMEDIRECTORY = os.getenv("GITLABCI_ACMEDIRECTORY_V2", "https://acme-staging-v02.api.letsencrypt.org/directory")
DNSHOST = os.getenv("GITLABCI_DNSHOST")
DNSHOSTIP = os.getenv("GITLABCI_DNSHOSTIP")
DNSZONE = os.getenv("GITLABCI_DNSZONE")
DNSPORT = os.getenv("GITLABCI_DNSPORT", "53")
DNSTTL = os.getenv("GITLABCI_DNSTTL", "10")
TSIGKEYNAME = os.getenv("GITLABCI_TSIGKEYNAME")
TSIGKEYVALUE = os.getenv("GITLABCI_TSIGKEYVALUE")
TSIGALGORITHM = os.getenv("GITLABCI_TSIGALGORITHM")
CONTACT = os.getenv("GITLABCI_CONTACT")

# generate simple config
def generate_config():
    # Account key
    account_key = NamedTemporaryFile(delete=False)
    Popen(["openssl", "genrsa", "-out", account_key.name, "2048"]).wait()

    # Domain key and CSR
    domain_key = NamedTemporaryFile(delete=False)
    domain_csr = NamedTemporaryFile(delete=False)
    Popen(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", domain_key.name,
        "-subj", "/CN={0}".format(DOMAIN), "-out", domain_csr.name]).wait()

    # acme-dns-tiny configuration
    parser = configparser.ConfigParser()
    parser.read("./example.ini")
    parser["acmednstiny"]["AccountKeyFile"] = account_key.name
    parser["acmednstiny"]["CSRFile"] = domain_csr.name
    parser["acmednstiny"]["ACMEDirectory"] = ACMEDIRECTORY
    if (CONTACT is not None
        and CONTACT != ""):
        parser["acmednstiny"]["Contacts"] = "mailto:{0}".format(CONTACT)
    else:
        del parser["acmednstiny"]["Contacts"]
    parser["TSIGKeyring"]["KeyName"] = TSIGKEYNAME
    parser["TSIGKeyring"]["KeyValue"] = TSIGKEYVALUE
    parser["TSIGKeyring"]["Algorithm"] = TSIGALGORITHM
    parser["DNS"]["Host"] = DNSHOST
    parser["DNS"]["Port"] = DNSPORT
    parser["DNS"]["Zone"] = DNSZONE
    parser["DNS"]["TTL"] = DNSTTL

    return account_key.name, domain_key.name, domain_csr.name, parser

# generate account and domain keys
def generate_acme_dns_tiny_config():
    # Simple configuration with good options
    account_key, domain_key, domain_csr, config = generate_config();
    os.remove(domain_key)

    goodCName = NamedTemporaryFile(delete=False)
    with open(goodCName.name, 'w') as configfile:
        config.write(configfile)

    # Simple configuration with good options, without contacts field
    account_key, domain_key, domain_csr, config = generate_config();
    os.remove(domain_key)

    config.remove_option("acmednstiny", "Contacts")

    goodCNameWithoutContacts = NamedTemporaryFile(delete=False)
    with open(goodCNameWithoutContacts.name, 'w') as configfile:
        config.write(configfile)

    # Simple configuration without CSR in configuration (will be passed as argument)
    account_key, domain_key, domain_csr, config = generate_config();
    os.remove(domain_key)

    cnameCSR = domain_csr
    config.remove_option("acmednstiny", "CSRFile")

    goodCNameWithoutCSR = NamedTemporaryFile(delete=False)
    with open(goodCNameWithoutCSR.name, 'w') as configfile:
        config.write(configfile)

    # Configuration with CSR containing a wildcard domain
    account_key, domain_key, domain_csr, config = generate_config();

    Popen(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", domain_key,
           "-subj", "/CN=*.{0}".format(DOMAIN), "-out", domain_csr]).wait()
    os.remove(domain_key)

    wildCName = NamedTemporaryFile(delete=False)
    with open(wildCName.name, 'w') as configfile:
        config.write(configfile)

    # Configuration with IP as DNS Host
    account_key, domain_key, domain_csr, config = generate_config();
    os.remove(domain_key)

    config["DNS"]["Host"] = DNSHOSTIP

    dnsHostIP = NamedTemporaryFile(delete=False)
    with open(dnsHostIP.name, 'w') as configfile:
        config.write(configfile)

    # Configuration with CSR using subject alt-name domain instead of CN (common name)
    account_key, domain_key, domain_csr, config = generate_config();

    san_conf = NamedTemporaryFile(delete=False)
    with open("/etc/ssl/openssl.cnf", 'r') as opensslcnf:
        san_conf.write(opensslcnf.read().encode("utf8"))
    san_conf.write("\n[SAN]\nsubjectAltName=DNS:{0},DNS:www.{0}\n".format(DOMAIN).encode("utf8"))
    san_conf.seek(0)
    Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key,
        "-subj", "/", "-reqexts", "SAN", "-config", san_conf.name,
        "-out", domain_csr]).wait()
    os.remove(san_conf.name)
    os.remove(domain_key)

    goodSAN = NamedTemporaryFile(delete=False)
    with open(goodSAN.name, 'w') as configfile:
        config.write(configfile)


    # Configuration with CSR containing a wildcard domain inside subjetcAltName
    account_key, domain_key, domain_csr, config = generate_config();

    wildsan_conf = NamedTemporaryFile(delete=False)
    with open("/etc/ssl/openssl.cnf", 'r') as opensslcnf:
        wildsan_conf.write(opensslcnf.read().encode("utf8"))
    wildsan_conf.write("\n[SAN]\nsubjectAltName=DNS:{0},DNS:*.{0}\n".format(DOMAIN).encode("utf8"))
    wildsan_conf.seek(0)
    Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key,
           "-subj", "/", "-reqexts", "SAN", "-config", wildsan_conf.name,
           "-out", domain_csr]).wait()
    os.remove(wildsan_conf.name)
    os.remove(domain_key)

    wildSAN = NamedTemporaryFile(delete=False)
    with open(wildSAN.name, 'w') as configfile:
        config.write(configfile)

    # Bad configuration with weak 1024 bit account key
    account_key, domain_key, domain_csr, config = generate_config();
    os.remove(domain_key)

    Popen(["openssl", "genrsa", "-out", account_key, "1024"]).wait()

    weakKey = NamedTemporaryFile(delete=False)
    with open(weakKey.name, 'w') as configfile:
        config.write(configfile)

    # Bad configuration with account key as domain key
    account_key, domain_key, domain_csr, config = generate_config();
    os.remove(domain_key)

    # Create a new CSR signed with the account key instead of domain key
    Popen(["openssl", "req", "-new", "-sha256", "-key", account_key,
        "-subj", "/CN={0}".format(DOMAIN), "-out", domain_csr]).wait()

    accountAsDomain = NamedTemporaryFile(delete=False)
    with open(accountAsDomain.name, 'w') as configfile:
        config.write(configfile)

    # Create config parser from the good default config to generate custom configs
    account_key, domain_key, domain_csr, config = generate_config();
    os.remove(domain_key)

    invalidTSIGName = NamedTemporaryFile(delete=False)
    config["TSIGKeyring"]["KeyName"] = "{0}.invalid".format(TSIGKEYNAME)
    with open(invalidTSIGName.name, 'w') as configfile:
        config.write(configfile)

    # Create config parser from the good default config to generate custom configs
    account_key, domain_key, domain_csr, config = generate_config();
    os.remove(domain_key)

    missingDNS = NamedTemporaryFile(delete=False)
    config["DNS"] = {}
    with open(missingDNS.name, 'w') as configfile:
        config.write(configfile)

    return {
        # configs
        "goodCName": goodCName.name,
        "goodCNameWithoutContacts": goodCNameWithoutContacts.name,
        "goodCNameWithoutCSR": goodCNameWithoutCSR.name,
        "wildCName": wildCName.name,
        "dnsHostIP": dnsHostIP.name,
        "goodSAN": goodSAN.name,
        "wildSAN": wildSAN.name,
        "weakKey": weakKey.name,
        "accountAsDomain": accountAsDomain.name,
        "invalidTSIGName": invalidTSIGName.name,
        "missingDNS": missingDNS.name,
        # CName CSR file to use with goodCNameWithoutCSR as argument
        "cnameCSR": domain_csr,
    }

# generate two account keys to roll over them
def generate_acme_account_rollover_config():
    # Old account is directly created by the config generator
    old_account_key, domain_key, domain_csr, config = generate_config()
    os.remove(domain_key)

    # New account key
    new_account_key = NamedTemporaryFile(delete=False)
    Popen(["openssl", "genrsa", "-out", new_account_key.name, "2048"]).wait()

    rolloverAccount = NamedTemporaryFile(delete=False)
    with open(rolloverAccount.name, 'w') as configfile:
        config.write(configfile)

    return {
        # config and keys (returned to keep files on system)
        "config": rolloverAccount.name,
        "oldaccountkey": old_account_key,
        "newaccountkey": new_account_key.name
    }

# generate an account key to delete it
def generate_acme_account_deactivate_config():
    # Account key is created by the by the config generator
    account_key, domain_key, domain_csr, config = generate_config()
    os.remove(domain_key)

    deactivateAccount = NamedTemporaryFile(delete=False)
    with open(deactivateAccount.name, 'w') as configfile:
        config.write(configfile)

    return {
        "config": deactivateAccount.name,
        "key": account_key
    }
