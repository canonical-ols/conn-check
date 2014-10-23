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

cd $(dirname $0)
REVNO=$(bzr revno)

cd $WHEELS_BRANCH_DIR
TAGS=$(bzr tags)

if [[ "$TAGS" == *"conn-check-r$REVNO"* ]]; then
	>&2 echo "revno already built and tagged, skipping"
else
	make test-wheels WHEELSDIR=$WHEELS_BRANCH_DIR
	bzr add *.whl
	bzr commit -m "Updating wheels from ${CONN_CHECK_REVNO}"
	bzr tag -d $WHEELS_BRANCH_DIR --force conn-check-r$CONN_CHECK_REVNO
	bzr push -d $WHEELS_BRANCH_DIR $WHEELS_BRANCH
fi

exit 0
