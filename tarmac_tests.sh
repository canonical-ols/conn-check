#!/bin/sh
set -e

# Build and test conn-check
make clean build test
# Build sphinx docs and send webhook to readthedocs to update conn-check.rtfd.org
make docs update-rtd
