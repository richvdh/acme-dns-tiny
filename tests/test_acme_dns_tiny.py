import unittest, sys, os
from subprocess import Popen, PIPE
from io import StringIO
import dns.version
import acme_dns_tiny
from tests.config_factory import generate_acme_dns_tiny_config
from tools.acme_account_delete import account_delete
import logassert

ACMEDirectory = os.getenv("GITLABCI_ACMEDIRECTORY", "https://acme-staging.api.letsencrypt.org/directory")

class TestACMEDNSTiny(unittest.TestCase):
    "Tests for acme_dns_tiny.get_crt()"

    @classmethod
    def setUpClass(self):
        print("Init acme_dns_tiny with python modules:".join(os.linesep))
        print("  - dns python:{0}{1}".format(dns.version.version, os.linesep))
        logassert.setup(self, 'acme_dns_tiny_logger')
        self.configs = generate_acme_dns_tiny_config()
        super(TestACMEDNSTiny, self).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    @classmethod
    def tearDownClass(self):
        # delete account key registration at end of tests
        account_delete(self.configs["accountkey"].name, ACMEDirectory)
        # close temp files correctly
        for tmpfile in self.configs:
            self.configs[tmpfile].close()
        super(TestACMEDNSTiny, self).tearDownClass()

    def test_success_cn(self):
        """ Successfully issue a certificate via common name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        result = acme_dns_tiny.main([self.configs['goodCName'].name])
        sys.stdout.seek(0)
        crt = sys.stdout.read().encode("utf8")
        sys.stdout = old_stdout
        out, err = Popen(["openssl", "x509", "-text", "-noout"], stdin=PIPE,
            stdout=PIPE, stderr=PIPE).communicate(crt)
        self.assertIn("BEGIN", crt.decode("utf8"))
        self.assertIn("Issuer", out.decode("utf8"))

    def test_success_dnshost_ip(self):
        """ When DNS Host is an IP, DNS resolution have to fail without error """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        result = acme_dns_tiny.main([self.configs['dnsHostIP'].name])
        self.assertLoggedInfo("A and/or AAAA DNS resources not found for configured dns host: we will use either resource found if exists or directly the DNS Host configuration.")
        sys.stdout.seek(0)
        crt = sys.stdout.read().encode("utf8")
        sys.stdout = old_stdout
        out, err = Popen(["openssl", "x509", "-text", "-noout"], stdin=PIPE,
            stdout=PIPE, stderr=PIPE).communicate(crt)
        self.assertIn("BEGIN", crt.decode("utf8"))
        self.assertIn("Issuer", out.decode("utf8"))

    def test_success_san(self):
        """ Successfully issue a certificate via subject alt name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        result = acme_dns_tiny.main([self.configs['goodSAN'].name])
        sys.stdout.seek(0)
        crt = sys.stdout.read().encode("utf8")
        sys.stdout = old_stdout
        out, err = Popen(["openssl", "x509", "-text", "-noout"], stdin=PIPE,
            stdout=PIPE, stderr=PIPE).communicate(crt)
        self.assertIn("BEGIN", crt.decode("utf8"))
        self.assertIn("Issuer", out.decode("utf8"))

    def test_success_cli(self):
        """ Successfully issue a certificate via command line interface """
        crt, err = Popen([
            "python3", "acme_dns_tiny.py", self.configs['goodCName'].name
        ], stdout=PIPE, stderr=PIPE).communicate()
        out, err = Popen(["openssl", "x509", "-text", "-noout"], stdin=PIPE,
            stdout=PIPE, stderr=PIPE).communicate(crt)
        self.assertIn("BEGIN", crt.decode("utf8"))
        self.assertIn("Issuer", out.decode("utf8"))

    def test_weak_key(self):
        """ Let's Encrypt rejects weak keys """
        try:
            result = acme_dns_tiny.main([self.configs['weakKey'].name])
        except Exception as e:
            result = e
        self.assertIsInstance(result, ValueError)
        self.assertIn("Key too small", result.args[0])

    def test_account_key_domain(self):
        """ Can't use the account key for the CSR """
        try:
            result = acme_dns_tiny.main([self.configs['accountAsDomain'].name])
        except Exception as e:
            result = e
        self.assertIsInstance(result, ValueError)
        self.assertIn("Certificate public key must be different than account key", result.args[0])

    def test_failure_dns_update_tsigkeyname(self):
        """ Fail to update DNS records by invalid TSIG Key name """
        try:
            result = acme_dns_tiny.main([self.configs['invalidTSIGName'].name])
        except Exception as e:
            result = e
        self.assertIsInstance(result, ValueError)
        self.assertIn("Error updating DNS", result.args[0])

    def test_failure_notcompleted_configuration(self):
        """ Configuration file have to be completed """
        try:
            result = acme_dns_tiny.main([self.configs['missingDNS'].name])
        except Exception as e:
            result = e
        self.assertIsInstance(result, ValueError)
        self.assertIn("Some required settings are missing.", result.args[0])

if __name__ == "__main__":
    unittest.main()
