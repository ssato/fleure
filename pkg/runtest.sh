#! /bin/bash
set -ex

flake8 --doctests fleure tests
pylint --disable=invalid-name,locally-disabled fleure
python -m nose -v --with-doctest --all-modules --where tests --with-coverage --cover-tests
