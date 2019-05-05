#! /bin/bash
set -ex

pip-3 install -r pkg/test_requirements.txt
flake8-3 --doctests fleure tests
# .. note::
#    pylint may exit w/ !0 code even if there are not errors but warnings.
pylint-3 --disable=invalid-name,locally-disabled fleure || :
python3 -m nose -v --with-doctest --all-modules --where fleure --with-coverage --cover-tests
