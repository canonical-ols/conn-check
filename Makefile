ENV=virtualenv
WHEELSDIR=./wheels

$(ENV):
	virtualenv $(ENV)

build: $(ENV)
	$(ENV)/bin/pip install -r devel-requirements.txt
	$(ENV)/bin/python setup.py develop

test:
	$(ENV)/bin/nosetests

clean:
	-rm -r $(ENV)
	-rm -r $(WHEELSDIR)
	find . -name "*.pyc" -delete

install-debs:
	sudo xargs --arg-file deb-requirements.txt apt-get install -y

cmd:
	@echo $(ENV)/bin/conn-check

pip-wheel:
	@$(ENV)/bin/pip install wheel

$(WHEELSDIR):
	mkdir $(WHEELSDIR)

build-wheels: pip-wheel $(WHEELSDIR)
	$(ENV)/bin/pip wheel --wheel-dir=$(WHEELSDIR) .


.PHONY: test build pip-wheel build-wheels install-debs clean cmd
.DEFAULT_GOAL := test
