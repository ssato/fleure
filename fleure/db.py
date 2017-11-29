#
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Satoru SATOH <ssato@redhat.com>
# License: GPLv3+
#
"""fleure DB frontend.
"""
from __future__ import absolute_import, print_function

import argparse
import glob
import gzip
import itertools
import logging
import os.path
import os
import pwd
import sqlite3
import subprocess
import sys

import anyconfig


LOG = logging.getLogger(__name__)
LOG.addHandler(logging.StreamHandler())
LOG.setLevel(logging.INFO)


def make_cache(repos, options, root=os.path.sep):
    """
    :param repos: List of repo IDs
    :param root: Root dir in which cachdir, e.g. /var/cache/dnf/, exists
    """
    ropts = itertools.chain.from_iterable(("--enablerepo", r) for r in repos)
    cmd = ["dnf", "makecache", "--installroot", os.path.abspath(root),
           "--disablerepo", "*"] + list(ropts) + options
    subprocess.check_call(cmd)


def find_uixmlgz_path(repo, root=os.path.sep):
    """
    updateinfo.xml.gz path in dnf:
        /var/cache/dnf/<repo>-*/repodata/<checksum>-updateinfo.xml.gz
    or
        /var/tmp/dnf-<user>-*/<repo>-*/repodata/<checksum>-updateinfo.xml.gz

      where repo is repo id, e.g. "rhel-7-server-rpms"
            checksum is checksum of xml.gz file, e.g. 531b74...

    .. todo:: How to change cache root wiht dnf's option?

    :param repo: Repo ID, e.g. rhel-7-server-rpms (RH CDN)
    :param root: Root dir in which cachdir, e.g. /var/cache/dnf/, exists
    :return: Path of the latest updateinfo.xml.gz or None if not found
    """
    uid = os.getuid()
    user = pwd.getpwuid(uid).pw_name
    rcdir = "/var/cache/dnf/" if uid == 0 else "/var/tmp/dnf-{user}-*/"
    pathf = os.path.join(rcdir, "{repo}-*/repodata/*-updateinfo.xml.gz")
    paths = sorted(glob.glob(pathf.format(repo=repo, root=root, user=user)),
                   key=os.path.getctime, reverse=True)
    return paths[0] if paths else None


def _create_table_statement(name, keys, auto_id=False):
    """
    :param name: Table name
    :param keys: Keys
    :param auto_id: Generate unique ID if True
    :return: SQL statement to create a table
    """
    if auto_id:
        params = ", ".join(k + " TEXT" for k in keys if k != "id")
        stmt = ("CREATE TABLE IF NOT EXISTS '{}' "
                "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "{}, UNIQUE(id))").format(name, params)
    else:
        params = ", ".join(k + (" TEXT PRIMARY KEY" if k == id else " TEXT")
                           for k in keys)
        stmt = ("CREATE TABLE IF NOT EXISTS '{}' "
                "({}, UNIQUE(id))".format(name, params))

    return stmt


def _get_value(dic, key):
    """
    :param dic: nested dict holding a value for key
    :return: Value for given key
    """
    candidate = dic.get(key, None)
    if candidate is None:
        return None
    elif isinstance(candidate, dict):
        # Search value with the new key found at first recursively.
        return _get_value(candidate, candidate.keys()[0])
    elif isinstance(candidate, list):
        return _get_value(candidate[0], key)  # Workaround for invalid ones.

    return candidate


def _exec_sql_stmt(cur, stmt, values=None):
    """
    :param cur: :class:`sqlite3.Cursor` object
    :param stmt: SQL statement to execute
    """
    try:
        return (cur.execute(stmt)
                if values is None else cur.execute(stmt, values))
    except (sqlite3.OperationalError, sqlite3.IntegrityError,
            sqlite3.InterfaceError):
        LOG.error("Could not execute: %s, %r", stmt, values)
        raise


def _insert_values(cur, name, keys, values, auto_id=False):
    """
    :param cur: :class:`sqlite3.Cursor` object
    :param name: Name of the table to insert data
    :param keys: Key names for values
    :param values:
        Values to insert. The order of items and the length are same as `key`.
    :param auto_id: Generate unique ID if True and id was not given
    """
    if any(v is None for v in values):
        keys = [k for k, v in itertools.izip(keys, values) if v is not None]
        values = [v for v in values if v is not None]
        stmt = ("INSERT OR IGNORE INTO {}({}) VALUES ({})"
                "".format(name, ", ".join(keys),
                          ", ".join("?" for v in values)))
    elif auto_id:
        stmt = ("INSERT OR IGNORE INTO {}({}) VALUES ({})"
                "".format(name, ", ".join(keys),
                          ", ".join("?" for v in values)))
    else:
        stmt = ("INSERT OR IGNORE INTO {} VALUES ({})"
                "".format(name, ", ".join("?" for v in values)))

    _exec_sql_stmt(cur, stmt, values)


def _fetch_id_from_table(cur, name, keys, values, key):
    """
    :param cur: :class:`sqlite3.Cursor` object
    :param name: Name of the table to insert data
    :param keys: Key names for values
    :param values:
        Values to insert. The order of items and the length are same as `key`.
    :param key: Key name to fetch the value
    """
    pred = " AND ".join("{} = '{}'".format(*t) for t in zip(keys, values))
    stmt = ("SELECT {} FROM {} WHERE {}".format(key, name, pred))
    return _exec_sql_stmt(cur, stmt).fetchall()[0][0]


def _is_ref(ref):
    """
    :param ref: Reference dict
    """
    return ("reference" in ref and "@attrs" in ref["reference"] and
            "id" in ref["reference"]["@attrs"])


def save_uidata_to_sqlite(uidata, outdir):
    """
    uidata:
        {"updates": [{"update": {...}, ...]}

    :param uidata: Updateinfo data (nested dict) to save
    :param outdir: Dir to save outputs
    """
    ups = [u["update"] for u in uidata["updates"] if "update" in u]
    dbpath = os.path.join(outdir, "updateinfo.db")

    if not ups:
        raise ValueError("Empty updatainfo data!")

    with sqlite3.connect(dbpath) as conn:
        cur = conn.cursor()

        # 1. Create tables
        pkeys = ("name", "version", "release", "epoch", "arch", "src")
        rkeys = ("id", "title", "type", "href")
        ukeys = ("id", "title", "summary", "description", "solution",
                 "issued", "updated", "release", "severity",
                 "reboot_suggested")  # optional: release, severity, ...

        _exec_sql_stmt(cur,
                       _create_table_statement("packages", pkeys,
                                               auto_id=True))
        _exec_sql_stmt(cur, _create_table_statement("refs", rkeys))
        _exec_sql_stmt(cur, _create_table_statement("updates", ukeys))

        _exec_sql_stmt(cur, "PRAGMA foreign_keys = ON")
        conn.commit()

        _exec_sql_stmt(cur,
                       "CREATE TABLE IF NOT EXISTS update_packages "
                       "(uid TEXT, pid INTEGER, "
                       " FOREIGN KEY(uid) REFERENCES updates(id), "
                       " FOREIGN KEY(pid) REFERENCES packages(id))")
        _exec_sql_stmt(cur,
                       "CREATE TABLE IF NOT EXISTS update_refs "
                       "(uid TEXT, rid TEXT, "
                       " FOREIGN KEY(uid) REFERENCES updates(id), "
                       " FOREIGN KEY(rid) REFERENCES refs(id))")
        conn.commit()

        # 2. Insert data
        for upd in ups:
            vals = [_get_value(upd, k) for k in ukeys]
            _insert_values(cur, "updates", ukeys, vals)

            pkgs = upd["pkglist"]["collection"]
            if "@children" in pkgs:
                pkgs = (p["package"]["@attrs"] for p in pkgs["@children"]
                        if "package" in p)
            else:
                pkgs = [pkgs["package"]["@attrs"]] if "package" in pkgs else []
            for pkg in pkgs:
                vals = tuple(pkg[k] for k in pkeys)
                _insert_values(cur, "packages", pkeys, vals, auto_id=True)
                conn.commit()

                pid = _fetch_id_from_table(cur, "packages", pkeys, vals, "id")
                _insert_values(cur, "update_packages", ("uid", "pid"),
                               (upd["id"], pid))
                conn.commit()

            refs = upd.get("references", [])
            if isinstance(refs, list):  # It has errata/rhbz references.
                refs = (r["reference"]["@attrs"] for r in refs if _is_ref(r))
                for ref in refs:
                    vals = tuple(ref[k] for k in rkeys)
                    _insert_values(cur, "refs", rkeys, vals)
                    _insert_values(cur, "update_refs", ("uid", "rid"),
                                   (upd["id"], ref["id"]))
            conn.commit()
        conn.commit()

    LOG.info("Save db: %s", dbpath)


def convert_uixmlgz(repo, outdir, root=os.path.sep):
    """
    :param repo: Repo ID, e.g. rhel-7-server-rpms (RH CDN)
    :param outdir: Dir to save outputs
    :param root: Root dir in which cachdir, e.g. /var/cache/dnf/, exists
    :return: True if success and False if not
    """
    uixmlgz = find_uixmlgz_path(repo, root=root)
    if uixmlgz is None:
        LOG.warn("Could not find updateinfo.xml.gz: repo=%s, root=%s",
                 repo, root)
        return False

    with gzip.open(uixmlgz) as inp:
        # FIXME: Not work as expected, 'ParseError: not well-formed ...'
        # uidata = anyconfig.load(inp, ac_parser="xml")
        uidata = anyconfig.loads(inp.read(), ac_parser="xml")

    if not os.path.exists(outdir):
        LOG.info("Creating dir to save results: %s", outdir)
        os.makedirs(outdir)
    elif not os.path.isdir(outdir):
        raise RuntimeError("Output dir '%s' is not a dir!" % outdir)

    # 1. Save as JSON file.
    anyconfig.dump(uidata, os.path.join(outdir, "updateinfo.json"))

    # 2. Convert and save SQLite database.
    try:
        save_uidata_to_sqlite(uidata, outdir)
    except (AttributeError, KeyError):
        raise


def make_parser():
    """Parse arguments.
    """
    defaults = dict(verbose=1, repos=[], workdir=os.curdir, makecache=False)
    psr = argparse.ArgumentParser()
    psr.set_defaults(**defaults)

    add_arg = psr.add_argument
    add_arg("-M", "--makecache", action="store_true",
            help="Specify this if to make cache in advance")
    add_arg("-w", "--workdir", help="Working dir [%(workdir)s]" % defaults)
    add_arg("-r", "--repo", dest="repos", action="append",
            help="Yum repo to fetch errata info, e.g. 'rhel-x86_64-server-6'. "
                 "It can be given multiple times to specify multiple yum "
                 "repos. If any repos are not given by this option, repos are "
                 "guess from data in RPM DBs automatically, and please not "
                 "that any other repos are disabled if this option was set.")
    add_arg("-v", "--verbose", action="count", dest="verbosity",
            help="Verbose mode")
    add_arg("-D", "--debug", action="store_const", dest="verbosity",
            const=2, help="Debug mode (same as -vv)")

    return psr


def main(argv=None):
    """Cli main.
    """
    if argv is None:
        argv = sys.argv[1:]

    psr = make_parser()
    args = psr.parse_args(argv)

    if not args.repos:
        psr.print_help()
        sys.exit(0)

    workdir = args.workdir
    if not os.path.exists(workdir):
        os.makedirs(workdir)

    if args.makecache:
        make_cache(args.repos, ["--verbose" if args.verbose else "--quiet"],
                   root=workdir)

    outdir = os.path.join(workdir, "out")
    for repo in args.repos:
        convert_uixmlgz(repo, outdir, root=workdir)


if __name__ == '__main__':
    main()

# vim:sw=4:ts=4:et:
