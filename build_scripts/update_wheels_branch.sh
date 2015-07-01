#!/bin/bash
set -e

if [[ -z "$WHEELS_BRANCH_DIR" ]]; then
	>&2 echo "Please set the WHEELS_BRANCH_DIR variable first"
	exit 2
fi

if [[ -z "$CONN_CHECK_REVNO" ]]; then
	>&2 echo "Please set the CONN_CHECK_REVNO variable first"
	exit 2
fi

if [[ -z "$WHEELS_BRANCH" ]]; then
	>&2 echo "Please set the WHEELS_BRANCH variable first"
	exit 2
fi

if [[ -z "$WHEELS_BRANCH_DIR" ]]; then
	>&2 echo "Please set the WHEELS_BRANCH_DIR variable first"
	exit 2
fi

DIR=$(dirname $(dirname $0))

cd $DIR
REVNO=$(bzr revno)

cd $WHEELS_BRANCH_DIR
TAGS=$(bzr tags)

if [[ "$TAGS" == *"conn-check-r$REVNO"* ]]; then
	>&2 echo "revno already built and tagged, skipping"
else
	cd $DIR
	ln -s $WHEELS_BRANCH_DIR $WHEELS_DIR
	# Ignore the error if it doesn't exist, but don't try to --force it
	rm -r $WHEELS_BRANCH_DIR 2>/dev/null
	make test-wheels

	cd $WHEELS_BRANCH_DIR
	bzr add *.whl
	bzr commit -m "Updating wheels from ${CONN_CHECK_REVNO}"
	bzr tag -d $WHEELS_BRANCH_DIR --force conn-check-r$CONN_CHECK_REVNO
	bzr tag -d $WHEELS_BRANCH_DIR --force $CONN_CHECK_REVNO

	cd $DIR
	rm -f ./wheels
fi

exit 0
