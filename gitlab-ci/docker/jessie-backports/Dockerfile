FROM debian:jessie-backports

RUN apt-get update
RUN apt-get upgrade

# Minimal tools required by acme-dns-tiny CI
RUN apt-get install -y \
	python3-coverage \
	python3-pip

RUN apt-get install -y \
	-t jessie-backports \
	python3-configargparse \
	python3-dnspython


# Allows run python3-coverage with same command than manual install by pip
RUN update-alternatives --install \
	/usr/bin/coverage \
	coverage \
	/usr/bin/python3-coverage \
	1
