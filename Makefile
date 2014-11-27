ENV=virtualenv
WHEELSDIR=./wheels
WHEELS_BRANCH=lp:~ubuntuone-hackers/conn-check/wheels
WHEELS_BRANCH_DIR=/tmp/conn-check-wheels
CONN_CHECK_REVNO=$(shell bzr revno)
CONN_CHECK_VERSION=$(shell cat conn_check/version.txt)
CONN_CHECK_PPA=ppa:wesmason/conn-check

$(ENV):
	virtualenv $(ENV)

build: $(ENV)
	$(ENV)/bin/pip install -r devel-requirements.txt
	$(ENV)/bin/python setup.py develop

test: $(ENV)
	$(ENV)/bin/nosetests

clean-wheels:
	-rm -r $(WHEELSDIR)

clean: clean-wheels
	-rm -r $(ENV)
	-rm -r dist
	-rm -r build
	-rm -r conn_check.egg-info
	find . -name "*.pyc" -delete

install-debs:
	sudo xargs --arg-file deb-dependencies.txt apt-get install -y

install-deb-pkg-debs: install-debs
	sudo apt-get install -y build-essential packaging-dev dh-make

build-deb: $(ENV)
	-rm conn-check_$(CONN_CHECK_VERSION)-*_*
	-rm dist/conn-check-$(CONN_CHECK_VERSION).tar.gz
	$(ENV)/bin/python setup.py sdist
	cp dist/conn-check-$(CONN_CHECK_VERSION).tar.gz conn-check_$(CONN_CHECK_VERSION).orig.tar.gz
	debuild -S -sa

update-ppa:
	cd .. && dput $(CONN_CHECK_PPA) conn-check_$(CONN_CHECK_VERSION)-*_source.changes

cmd:
	@echo $(ENV)/bin/conn-check

pip-wheel: $(ENV)
	@$(ENV)/bin/pip install wheel

$(WHEELSDIR):
	mkdir $(WHEELSDIR)

build-wheels: pip-wheel $(WHEELSDIR) $(ENV)
	$(ENV)/bin/pip wheel --wheel-dir=$(WHEELSDIR) .

build-wheels-extra: pip-wheel $(WHEELSDIR) $(ENV)
	$(ENV)/bin/pip wheel --wheel-dir=$(WHEELSDIR) -r ${EXTRA}-requirements.txt

build-wheels-all-extras: pip-wheel $(WHEELSDIR) $(ENV)
	ls *-requirements.txt | grep -vw 'devel\|test' | xargs -L 1 \
		$(ENV)/bin/pip wheel --wheel-dir=$(WHEELSDIR) -r

test-wheels: build-wheels build-wheels-all-extras
	$(ENV)/bin/pip install -r test-requirements.txt
	$(ENV)/bin/pip install --ignore-installed --no-index --find-links $(WHEELSDIR) -r requirements.txt
	ls *-requirements.txt | grep -vw 'devel\|test' | xargs -L 1 \
		$(ENV)/bin/pip install --ignore-installed --no-index --find-links $(WHEELSDIR) -r
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
	$(PWD)/build_scripts/update_wheels_branch.sh

upload: build test pip-wheel
	$(ENV)/bin/python setup.py sdist bdist_wheel upload
	@echo
	@echo "Don't forget: bzr tag $(CONN_CHECK_VERSION) && bzr push"


.PHONY: test build pip-wheel build-wheels build-wheels-extra build-wheels-all test-wheels install-debs clean cmd upload install-build-debs
.DEFAULT_GOAL := test
