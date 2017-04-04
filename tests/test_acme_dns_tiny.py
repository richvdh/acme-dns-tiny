import unittest, sys, os, subprocess
from io import StringIO
import dns.version
import acme_dns_tiny
from tests.config_factory import generate_acme_dns_tiny_config
from tools.acme_account_delete import account_delete

ACMEDirectory = os.getenv("GITLABCI_ACMEDIRECTORY", "https://acme-staging.api.letsencrypt.org/directory")

class TestACMEDNSTiny(unittest.TestCase):
    "Tests for acme_dns_tiny.get_crt()"

    @classmethod
    def setUpClass(self):
        print("Init acme_dns_tiny with python modules:".join(os.linesep))
        print("  - dns python:{0}{1}".format(dns.version.version, os.linesep))
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

    # helper function to run openssl command
    def openssl(self, command, options, communicate=None):
        openssl = subprocess.Popen(["openssl", command] + options,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out

    # helper function to valid success by making assertion on returned certificate chain
    def assertCertificateChain(self, certificateChain):
        # Output have to contains two certiicates
        certlist = certificateChain.split("-----BEGIN CERTIFICATE-----")
        self.assertEqual(2, len(certlist))
        self.assertIn("-----END CERTIFICATE-----{0}".format(os.linesep), certlist[0])
        self.assertIn("-----END CERTIFICATE-----{0}".format(os.linesep), certlist[1])
        # Use openssl to check validity of chain and simple test of readability
        readablecertchain = self.openssl("x509", ["-text", "-noout"], certificateChain.encode("utf8"))
        self.assertIn("Issuer", readablecertchain)

    def test_success_cn(self):
        """ Successfully issue a certificate via common name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        acme_dns_tiny.main([self.configs['goodCName'].name])
        certchain = sys.stdout.getvalue()
        
        sys.stdout.close()
        sys.stdout = old_stdout
        
        self.assertCertificateChain(certchain)

    def test_success_dnshost_ip(self):
        """ When DNS Host is an IP, DNS resolution have to fail without error """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        with self.assertLogs(level='INFO') as adnslog:
            acme_dns_tiny.main([self.configs['dnsHostIP'].name])
        self.assertIn("INFO:acme_dns_tiny:A and/or AAAA DNS resources not found for configured dns host: we will use either resource found if exists or directly the DNS Host configuration.",
            adnslog.output)
        certchain = sys.stdout.getvalue()
        
        sys.stdout.close()
        sys.stdout = old_stdout
        
        self.assertCertificateChain(certchain)

    def test_success_san(self):
        """ Successfully issue a certificate via subject alt name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        acme_dns_tiny.main([self.configs['goodSAN'].name])
        certchain = sys.stdout.getvalue()
        
        sys.stdout.close()
        sys.stdout = old_stdout
        
        self.assertCertificateChain(certchain)

    def test_success_cli(self):
        """ Successfully issue a certificate via command line interface """
        certout, err = subprocess.Popen([
            "python3", "acme_dns_tiny.py", self.configs['goodCName'].name
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        
        certout.seek(0)
        certchain = certout.read().decode("utf8")
        
        certout.close()
        err.close()
        
        self.assertCertificateChain(certchain)

    def test_weak_key(self):
        """ Let's Encrypt rejects weak keys """
        self.assertRaisesRegex(ValueError,
                               "Key too small",
                               acme_dns_tiny.main, [self.configs['weakKey'].name])

    def test_account_key_domain(self):
        """ Can't use the account key for the CSR """
        self.assertRaisesRegex(ValueError,
                               "Certificate public key must be different than account key",
                               acme_dns_tiny.main, [self.configs['accountAsDomain'].name])

    def test_failure_dns_update_tsigkeyname(self):
        """ Fail to update DNS records by invalid TSIG Key name """
        self.assertRaisesRegex(ValueError,
                               "Error updating DNS",
                               acme_dns_tiny.main, [self.configs['invalidTSIGName'].name])

    def test_failure_notcompleted_configuration(self):
        """ Configuration file have to be completed """
        self.assertRaisesRegex(ValueError,
                               "Some required settings are missing\.",
                               acme_dns_tiny.main, [self.configs['missingDNS'].name])

if __name__ == "__main__":
    unittest.main()
