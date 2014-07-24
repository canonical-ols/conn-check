ENV=virtualenv

$(ENV):
	virtualenv $(ENV)

build: $(ENV)
	$(ENV)/bin/pip install -r requirements.txt -r devel-requirements.txt
	$(ENV)/bin/python setup.py develop

test:
	$(ENV)/bin/nosetests

clean:
	-rm -r $(ENV)
	find . -name "*.pyc" -delete

install-debs:
	sudo xargs --arg-file deb-requirements.txt apt-get install -y

cmd:
	@echo $(ENV)/bin/python conn_check/__init__.py


.PHONY: test build
.DEFAULT_GOAL := test
