FROM jessie

RUN apt-get update
RUN apt-get upgrade

# Add Jessie backports source
RUN apt-get install -y \
	software-properties-common

RUN add-apt-repository \
	"deb http://httpredir.debian.org/debian" \
	"jessie-backports" \
	"main"

RUN apt-get update

# Minimal tools required by acme-dns-tiny CI
RUN apt-get install -y \
	python3-coverage \
	python3-pip

RUN apt-get install -y \
	-t jessie-backports \
	python3-dnspython


# Allows run python3-coverage with same command than manual install by pip
RUN update-alternatives --install \
	/usr/bin/python3-coverage \
	coverage \
	/usr/bin/python3.4-coverage \
	1

RUN ln -s /etc/alternatives/coverage /usr/bin/coverage
