import unittest, os
import acme_dns_tiny
from tests.config_factory import generate_acme_account_deactivate_config
import tools.acme_account_deactivate

ACMEDirectory = os.getenv("GITLABCI_ACMEDIRECTORY_V2", "https://acme-staging-v02.api.letsencrypt.org/directory")

class TestACMEAccountDeactivate(unittest.TestCase):
    "Tests for acme_account_deactivate"

    @classmethod
    def setUpClass(self):
        configs = generate_acme_account_deactivate_config()
        self.config = configs["config"]
        self.account_key = configs["key"]
        acme_dns_tiny.main([self.config.name])
        super(TestACMEAccountDeactivate, self).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    @classmethod
    def tearDownClass(self):
        # Remove temporary files
        os.remove(self.config.name)
        os.remove(self.account_key)
        super(TestACMEAccountDeactivate, self).tearDownClass()

    def test_success_account_deactivate(self):
        """ Test success account key deactivate """
        with self.assertLogs(level='INFO') as accountdeactivatelog:
            tools.acme_account_deactivate.main(["--account-key", self.accountkey.name,
                                            "--acme-directory", ACMEDirectory])
        self.assertIn("INFO:acme_account_deactivate:Account key deactivated !",
            accountdeactivatelog.output)

if __name__ == "__main__":
    unittest.main()
