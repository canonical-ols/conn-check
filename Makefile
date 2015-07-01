ENV = virtualenv
WHEELS_DIR = ./wheels
WHEELS_BRANCH = lp:~ubuntuone-hackers/conn-check/wheels
WHEELS_BRANCH_DIR = /tmp/conn-check-wheels
CONN_CHECK_REVNO = $(shell bzr revno)
CONN_CHECK_VERSION = $(shell cat conn_check/version.txt)
CONN_CHECK_PPA = ppa:wesmason/conn-check
DEBIAN_PYTHON_CACHE_DIR = debian/pythoncache
DEBIAN_PYTHON_PACKAGES_FILTER = Twisted txAMQP pyOpenSSL pyasn1 PyYAML psycopg2 requests cffi pycparser six setuptools zope.interface pymongo
HERE = $(patsubst %/,%,$(dir $(realpath $(lastword $(MAKEFILE_LIST)))))
DOCS_DIR = $(HERE)/docs

$(ENV):
	virtualenv $(ENV)

build: $(ENV)
	$(ENV)/bin/pip install -r devel-requirements.txt
	$(ENV)/bin/python setup.py develop

test: $(ENV)
	$(ENV)/bin/nosetests

clean-wheels:
	-rm -r $(WHEELS_DIR)

clean-docs:
	-rm -r $(DOCS_DIR)/_build

clean: clean-wheels clean-docs
	-rm -r $(ENV)
	-rm -r dist
	-rm -r $(DEBIAN_PYTHON_CACHE_DIR)
	-rm -r conn_check.egg-info
	find . -name "*.pyc" -delete

install-debs:
	sudo xargs --arg-file deb-dependencies.txt apt-get install -y

install-deb-pkg-debs: install-debs
	sudo apt-get install -y build-essential packaging-dev dh-make

$(ENV)/bin/pip2tgz: $(ENV)
	$(ENV)/bin/pip install pip2pi

build-deb-pip-cache: $(ENV)/bin/pip2tgz
	mkdir -p $(DEBIAN_PYTHON_CACHE_DIR)
	ls *requirements.txt | grep -vw 'devel\|test' | xargs -I{} \
		cat {} | sort | uniq > debian-requirements-filtered.txt
	@echo '$(DEBIAN_PYTHON_PACKAGES_FILTER)' \
		| tr " " "\n" \
		| xargs -L 1 -I{} \
			sed -i '/^{}/d' debian-requirements-filtered.txt
	$(ENV)/bin/pip2tgz $(DEBIAN_PYTHON_CACHE_DIR) -r debian-requirements-filtered.txt
	-rm debian-requirements-filtered.txt
	@echo 'Removing upstream Debian python-* packages from cache..'
	@echo '$(DEBIAN_PYTHON_PACKAGES_FILTER)' \
		| tr " " "\n" \
		| xargs -L 1 -I{} find $(DEBIAN_PYTHON_CACHE_DIR) -maxdepth 2 -name '{}*' \
			| xargs rm -r
	$(ENV)/bin/dir2pi $(DEBIAN_PYTHON_CACHE_DIR)
	sed -i '/pythoncache/d' debian/source/include-binaries
	find debian/pythoncache -path "*.html" -prune -o -print >> debian/source/include-binaries

../conn-check_$(CONN_CHECK_VERSION).orig.tar.gz:
	$(ENV)/bin/python setup.py sdist
	cp dist/conn-check-$(CONN_CHECK_VERSION).tar.gz ../conn-check_$(CONN_CHECK_VERSION).orig.tar.gz

build-deb: build-deb-pip-cache ../conn-check_$(CONN_CHECK_VERSION).orig.tar.gz
	-rm ../conn-check_$(CONN_CHECK_VERSION)-*
	debuild -S -sa

test-build-deb: build-deb
	debuild

update-ppa:
	cd .. && dput $(CONN_CHECK_PPA) conn-check_$(CONN_CHECK_VERSION)-*_source.changes

cmd:
	@echo $(ENV)/bin/conn-check

fw-cmd:
	@echo $(ENV)/bin/conn-check-export-fw

fw-convert-cmd:
	@echo $(ENV)/bin/conn-check-convert-fw

pip-wheel: $(ENV)
	@$(ENV)/bin/pip install wheel

$(WHEELS_DIR):
	mkdir $(WHEELS_DIR)

build-wheels: pip-wheel $(WHEELS_DIR) $(ENV)
	$(ENV)/bin/pip wheel --wheel-dir=$(WHEELS_DIR) .

build-wheels-extra: pip-wheel $(WHEELS_DIR) $(ENV)
	$(ENV)/bin/pip wheel --wheel-dir=$(WHEELS_DIR) -r ${EXTRA}-requirements.txt

build-wheels-all-extras: pip-wheel $(WHEELS_DIR) $(ENV)
	ls *-requirements.txt | grep -vw 'devel\|test' | xargs -L 1 \
		$(ENV)/bin/pip wheel --wheel-dir=$(WHEELS_DIR) -r

test-wheels: build-wheels build-wheels-all-extras
	$(ENV)/bin/pip install -r test-requirements.txt
	$(ENV)/bin/pip install --ignore-installed --no-index --find-links $(WHEELS_DIR) -r requirements.txt
	ls *-requirements.txt | grep -vw 'devel\|test' | xargs -L 1 \
		$(ENV)/bin/pip install --ignore-installed --no-index --find-links $(WHEELS_DIR) -r
	$(MAKE) test

$(WHEELS_BRANCH_DIR):
	bzr branch $(WHEELS_BRANCH) $(WHEELS_BRANCH_DIR)

update-wheel-branch: $(WHEELS_BRANCH_DIR)
	@$(ENV)/bin/pip install --upgrade setuptools
	@$(ENV)/bin/pip install --upgrade pip
	bzr pull -d $(WHEELS_BRANCH_DIR)
	WHEELS_BRANCH=$(WHEELS_BRANCH) \
	WHEELS_BRANCH_DIR=$(WHEELS_BRANCH_DIR) \
	CONN_CHECK_REVNO=$(CONN_CHECK_REVNO) \
	WHEELS_DIR=$(WHEELS_DIR) \
	$(PWD)/build_scripts/update_wheels_branch.sh

upload: build test pip-wheel
	$(ENV)/bin/python setup.py sdist bdist_wheel upload
	@echo
	@echo "Don't forget: bzr tag $(CONN_CHECK_VERSION) && bzr push"

docs: TYPE=html
docs:
	cd $(DOCS_DIR) && $(MAKE) $(TYPE)

update-rtd:
	-curl -X POST http://readthedocs.org/build/conn-check


.PHONY: test build pip-wheel build-wheels build-wheels-extra build-wheels-all test-wheels install-debs clean cmd upload install-build-debs build-deb-pip-cache test-build-deb docs clean-docs
.DEFAULT_GOAL := test
