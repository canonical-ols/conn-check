ENV=virtualenv
WHEELSDIR=./wheels

$(ENV):
	virtualenv $(ENV)

build: $(ENV)
	$(ENV)/bin/pip install -r devel-requirements.txt
	$(ENV)/bin/python setup.py develop

test: $(ENV)
	$(ENV)/bin/nosetests

clean:
	-rm -r $(ENV)
	-rm -r $(WHEELSDIR)
	find . -name "*.pyc" -delete

install-debs:
	sudo xargs --arg-file deb-requirements.txt apt-get install -y

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


.PHONY: test build pip-wheel build-wheels build-wheels-extra install-debs clean cmd
.DEFAULT_GOAL := test
