# How to test acme-dns-tiny

Testing acme-dns-tiny requires a bit of setup since it interacts with other servers
(Let's Encrypt's staging server) to test issuing fake certificates. This readme
explains how to setup and test acme-tiny yourself.

## Setup instructions

1. Setup environment variables:
  * Read top of monkey.py, all environnement variables used are defined there (top of file).
  * These variables corresponds to the configuration file you have to do when using in production.
  * If you don't own the gitlab project, you can set them on your build/test machine:
    `export GITLABCI_DOMAIN=travis-ci.gethttpsforfree.com`
  * Otherwise, you have to use your gitlab project to define environment variables for gitlab runners.
2. Install the test requirements on your build/test machine (automated by .gitlab-ci.yml for gitlab runners).
  * `cd /path/to/acme-dns-tiny`
  * `pip install --user -r tests/requirements.txt`
5. Run the test suit on your local.
  * `cd /path/to/acme-dns-tiny`
  * `coverage run --source ./ -m unittest tests`
