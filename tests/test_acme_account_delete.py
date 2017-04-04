import unittest, sys, os
import acme_dns_tiny
from tests.config_factory import generate_acme_account_delete_config
import tools.acme_account_delete
import logassert

ACMEDirectory = os.getenv("GITLABCI_ACMEDIRECTORY", "https://acme-staging.api.letsencrypt.org/directory")

class TestACMEAccountDelete(unittest.TestCase):
    "Tests for acme_account_delete"

    @classmethod
    def setUpClass(self):
        logassert.setup(self, 'acme_account_delete')
        self.accountkey = generate_acme_account_delete_config()
        super(TestACMEAccountDelete, self).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    @classmethod
    def tearDownClass(self):
        # close temp files correctly
        self.accountkey.close()
        super(TestACMEAccountDelete, self).tearDownClass()

    def test_success_account_delete(self):
        """ Test success account key delete """
        tools.acme_account_delete.main(["--account-key", self.accountkey.name,
                                        "--acme-directory", ACMEDirectory])
        self.assertLoggedInfo("Account key deleted !")

if __name__ == "__main__":
    unittest.main()
