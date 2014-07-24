ENV=virtualenv

$(ENV):
	virtualenv $(ENV)

build: $(ENV)
	$(ENV)/bin/pip install -r requirements.txt
	$(ENV)/bin/python setup.py develop

test:
	$(ENV)/bin/nosetests


.PHONY: test build
.DEFAULT_GOAL := test
