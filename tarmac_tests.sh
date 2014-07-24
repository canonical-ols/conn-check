#!/bin/sh
set -e

make clean
make build
make test
