#!/bin/bash
set -e

if [[ -z "$WHEELSDIR" ]]; then
	>&2 echo "Please set the WHEELSDIR variable first"
	exit 2
fi

cd $(dirname $0)
REVNO=$(bzr revno)

cd $WHEELSDIR
TAGS=$(bzr tags)

if [[ "$TAGS" == *"conn-check-r$REVNO"* ]]; then
	echo "revno already built and tagged, skipping"
	exit 1
fi

exit 0
