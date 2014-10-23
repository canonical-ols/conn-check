#!/bin/bash
set -e

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
	exit 1
fi

exit 0
