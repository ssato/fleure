#! /bin/bash
set -ex

pip-3 install -r pkg/test_requirements.txt
flake8-3 --doctests fleure tests
pylint-3 --disable=invalid-name,locally-disabled fleure
python3 -m nose -v --with-doctest --all-modules --where tests --with-coverage --cover-tests
