#!/bin/sh -e

BASEDIR=$(dirname `readlink -f $0`)
cd "${BASEDIR}"

pip install -r requirements-test.txt

echo
echo "--- RUN FLAKE8 ---"
echo

flake8 --statistics
