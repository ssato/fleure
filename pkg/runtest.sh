#! /bin/bash
set -ex

PY_VER=${1:-3}

pip-${PY_VER:?} install -r pkg/test_requirements.txt
flake8-${PY_VER:?} --doctests fleure tests
# .. note::
#    pylint may exit w/ !0 code even if there are not errors but warnings.
pylint-${PY_VER:?} --disable=invalid-name,locally-disabled fleure || :
python${PY_VER:?} -m nose -v --with-doctest --all-modules --where fleure --with-coverage --cover-tests
