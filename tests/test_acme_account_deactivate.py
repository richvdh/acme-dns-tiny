import unittest, os, time
import acme_dns_tiny
from tests.config_factory import generate_acme_account_deactivate_config
import tools.acme_account_deactivate

ACMEDirectory = os.getenv("GITLABCI_ACMEDIRECTORY_V2", "https://acme-staging-v02.api.letsencrypt.org/directory")

class TestACMEAccountDeactivate(unittest.TestCase):
    "Tests for acme_account_deactivate"

    @classmethod
    def setUpClass(self):
        self.configs = generate_acme_account_deactivate_config()
        try:
            acme_dns_tiny.main([self.configs['config']])
        except ValueError as err:
            if str(err).startswith("Error register"):
                raise ValueError("Fail test as account has not been registered correctly: {0}".format(err))

        super(TestACMEAccountDeactivate, self).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    @classmethod
    def tearDownClass(self):
        # Remove temporary files
        os.remove(self.configs['config'])
        os.remove(self.configs['key'])
        super(TestACMEAccountDeactivate, self).tearDownClass()

    def test_success_account_deactivate(self):
        """ Test success account key deactivate """
        with self.assertLogs(level='INFO') as accountdeactivatelog:
            tools.acme_account_deactivate.main(["--account-key", self.configs['key'],
                                            "--acme-directory", ACMEDirectory])
        self.assertIn("INFO:acme_account_deactivate:Account key deactivated !",
            accountdeactivatelog.output)

if __name__ == "__main__":
    unittest.main()
