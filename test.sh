#!/bin/sh -e

BASEDIR=$(dirname `readlink -f $0`)

pip install -r "${BASEDIR}/requirements-test.txt"

echo
echo "--- RUN FLAKE8 ---"
echo

flake8 --statistics "${BASEDIR}"

echo
echo "--- RUN UNIT TESTS ---"
echo
pytest -v --cov="${BASEDIR}" "${BASEDIR}/tests"
