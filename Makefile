ENV=virtualenv
WHEELSDIR=./wheels
WHEELS_BRANCH=lp:~ubuntuone-hackers/conn-check/wheels
WHEELS_BRANCH_DIR=/tmp/conn-check-wheels
CONN_CHECK_REVNO=$(shell bzr revno)

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
	find . -name "*.pyc" -delete

install-debs:
	sudo xargs --arg-file deb-dependencies.txt apt-get install -y

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
	bzr pull -d $(WHEELS_BRANCH_DIR)
	WHEELS_BRANCH_DIR=$(WHEELS_BRANCH_DIR) ./test_revno.sh || exit 0 \
	$(MAKE) test-wheels WHEELSDIR=$(WHEELS_BRANCH_DIR) \
	cd $(WHEELS_BRANCH_DIR) && bzr add *.whl && bzr commit -m "Updating wheels from $(CONN_CHECK_REVNO)" \
	bzr tag -d $(WHEELS_BRANCH_DIR) --force $(CONN_CHECK_REVNO) \
	bzr push -d $(WHEELS_BRANCH_DIR) $(WHEELS_BRANCH) \

upload: build test pip-wheel
	$(ENV)/bin/python setup.py sdist bdist_wheel upload
	@echo
	@echo "Don't forget: bzr tag" `cat conn_check/version.txt` '&& bzr push'


.PHONY: test build pip-wheel build-wheels build-wheels-extra build-wheels-all test-wheels install-debs clean cmd upload
.DEFAULT_GOAL := test
