import unittest, os
import acme_dns_tiny
from tests.config_factory import generate_acme_account_rollover_config
from tools.acme_account_deactivate import account_deactivate
import tools.acme_account_rollover

ACMEDirectory = os.getenv("GITLABCI_ACMEDIRECTORY_V2", "https://acme-staging-v02.api.letsencrypt.org/directory")

class TestACMEAccountRollover(unittest.TestCase):
    "Tests for acme_account_rollover"

    @classmethod
    def setUpClass(self):
        self.configs = generate_acme_account_rollover_config()
        acme_dns_tiny.main([self.configs['config']])
        super(TestACMEAccountRollover, self).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    @classmethod
    def tearDownClass(self):
        # deactivate account key registration at end of tests
        account_deactivate(self.configs["oldaccountkey"], ACMEDirectory)
        # close temp files correctly
        for tmpfile in self.configs:
            os.remove(self.configs[tmpfile])
        super(TestACMEAccountRollover, self).tearDownClass()

    def test_success_account_rollover(self):
        """ Test success account key rollover """
        with self.assertLogs(level='INFO') as accountrolloverlog:
            tools.acme_account_rollover.main(["--current", self.configs['oldaccountkey'],
                                          	    "--new", self.configs['newaccountkey'],
                                          	    "--acme-directory", ACMEDirectory])
        self.assertIn("INFO:acme_account_rollover:Account keys rolled over !",
            accountrolloverlog.output)

if __name__ == "__main__":
    unittest.main()
