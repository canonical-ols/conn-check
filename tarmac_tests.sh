#!/bin/sh
set -e

# Build and test conn-check
make clean build test docs
