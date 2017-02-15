#! /bin/bash
#
# A tiny script wrapping 'yum/dnf makecache'.
#
set -e

# Defaults:
DNF=$(which dnf 2>/dev/null || which yum 2>/dev/null) # Prefer dnf.
REPOS="
rhel-6-server-rpms
rhel-6-server-optional-rpms
rhel-6-server-extras-rpms
rhel-7-server-rpms
rhel-7-server-optional-rpms
rhel-7-server-extras-rpms
"
CONFDIR=/etc/fleure/db/

# main:
test -d ${CONFDIR} && (for f in ${CONFDIR}/*.conf; do test -f $f && source $f; done)

REPO_OPTS="--disablerepo '*'"
for repo in ${REPOS:?}; do REPO_OPTS="${REPO_OPTS} --enablerepo ${repo}"; done

${DNF:?} makecache ${REPO_OPTS}

# vim:sw=4:ts=4:et:
