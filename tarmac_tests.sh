#!/bin/sh
set -e

make clean
make build
make test

if [ "$BUILD_CONN_CHECK_WHEELS" = "true" ]; then
    # Update wheels branch with built packages
    make update-wheel-branch
fi

exit 0
