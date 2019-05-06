#
# Copyright (C) 2013 - 2017 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato@redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# pylint: disable=no-member
"""Module to make up RPM dependency graph.
"""
from __future__ import absolute_import

import logging
import itertools
import operator
import os.path

import networkx

try:
    import yum
    YUM_IS_AVAILABLE = True
except ImportError:
    YUM_IS_AVAILABLE = False

import anytemplate

import fleure.globals
import fleure.rpmutils
import fleure.utils

from fleure.globals import _


_E_ATTRS = dict(weight=1.0, )
LOG = logging.getLogger(__name__)


def _yum_list_installed(root=None, cachedir=None, persistdir=None):
    """
    List installed packages using an internal API of yum.

    :param root: RPM DB root dir
    :return: List of yum.rpmsack.RPMInstalledPackage objects
    """
    if not YUM_IS_AVAILABLE:
        return[]

    if root is None:
        root = "/var/lib/rpm"

    if persistdir is None:
        persistdir = root

    cachedir = os.path.join(root, "cache")
    sack = yum.rpmsack.RPMDBPackageSack(root, cachedir=cachedir,
                                        persistdir=persistdir)
    return sack.returnPackages()  # NOTE: 'gpg-pubkey' is not in this list.


def make_requires_dict(root=None, reverse=False, use_yum=False):
    """
    Returns RPM dependency relations map.

    :param root: RPM Database root dir or None (use /var/lib/rpm).
    :param reverse: Returns a dict such
        {required_RPM: [RPM_requires]} instead of a dict such
        {RPM: [RPM_required]} if True.
    :param use_yum: Use yum to get the installed RPMs list

    :return: Requirements relation map, {p: [required]} or {required: [p]}

    NOTEs:
     * X.required_packages returns RPMs required to install it (X instance).
       e.g. gc (X) requires libgcc

       where X = yum.rpmsack.RPMInstalledPackage

     * X.requiring_packages returns RPMs requiring it (X instance).
       e.g. libgcc (X) is required by gc

     * yum.rpmsack.RPMInstalledPackage goes away in DNF so that
       I have to find similar function in DNF.

       (see also: http://fedoraproject.org/wiki/Features/DNF)
    """
    def list_reqs(pkg):
        """List package requires.
        """
        fnc = "requiring_packages" if reverse else "required_packages"
        return sorted(x.name for x in getattr(pkg, fnc)())

    if use_yum:
        return dict((p.name, list_reqs(p)) for p in _yum_list_installed(root))

    ips = fleure.rpmutils.list_installed_rpms(root=root, resolv=True)

    if reverse:
        reqs = fleure.utils.uconcat([(r["name"], p["name"]) for r
                                     in p["requires"]] for p in ips)
        reqs = ((k, [tpl[1] for tpl in g]) for k, g
                in itertools.groupby(reqs, operator.itemgetter(0)))
    else:
        reqs = ((p["name"], sorted(r["name"] for r in p["requires"]))
                for p in ips)

    return dict(reqs)


def make_dependency_graph(root, reverse=True, rreqs=None, edge_attrs=None):
    """
    Make RPM dependency graph with using Networkx.DiGraph for given root.

    :param root: RPM Database root dir
    :param reverse: Resolve reverse dependency from required to requires
    :param rreqs: A dict represents RPM dependencies;
        {x: [package_requires_x]} or {x: [package_required_by_x]}.
    :param edge_attrs: Default edge attributes :: dict

    :return: networkx.DiGraph instance
    """
    if rreqs is None:
        rreqs = make_requires_dict(root, reverse)

    if edge_attrs is None:
        edge_attrs = _E_ATTRS

    graph = networkx.DiGraph()
    for key, vals in rreqs.items():
        graph.add_node(key, names=[key])
        graph.add_edges_from([(key, val, edge_attrs) for val in vals])

    # Remove edges of self cyclic nodes:
    graph.remove_edges_from(graph.selfloop_edges())

    return graph


def _make_depgraph_context(root, ers):
    """
    Make up context to generate RPM dependency graph w/ graphviz (sfdp) from
    the RPM database files for given host group.

    :param root: Root dir where 'var/lib/rpm' exists
    :param ers: List of errata dict, see :func:`analyze_errata` in fleure.main

    :return: { name :: str,
               groups :: [name :: str,
                          nodes :: [node :: { id :: Int, name :: str} ]],
               deps :: [(name_reqd :: str, name_reqs :: str)] }
    """
    graph = make_dependency_graph(root)

    # Package name vs. ID map:
    pmap = dict((n, "node_%d" % i) for i, n in enumerate(sorted(graph)))

    # setup package groups:
    pgs = [n for n in graph if not graph.predecessors(n)]

    # see :func:`rpmkit.updateinfo.main.analyze_errata`
    def _list_uns_by_etype(etype="rhsa"):
        """List update package names by errata type.
        """
        return fleure.utils.uniq(t[0] for t in ers[etype]["list_by_packages"])

    def _list_uns_by_sev(sev="critical"):
        """List update package names by severity of security errata.
        """
        return fleure.utils.uniq(u["name"] for u
                                 in ers["rhsa"]["list_%s_updates" % sev])

    def _mk_ps_g(graph, groups):
        """Make up package groups.
        """
        for name in graph:
            yield dict(id=pmap[name], name=name,
                       layers=([grp for grp, ns in groups.items()
                                if name in ns] + ["visible"]))

    groups = dict(roots=[n for n in pgs if graph.successors(n)],
                  standalones=[n for n in pgs if not graph.successors(n)],
                  rhsa=_list_uns_by_etype("rhsa"),
                  rhba=_list_uns_by_etype("rhba"),
                  rhea=_list_uns_by_etype("rhea"),
                  rhsa_cri=_list_uns_by_sev("critical"),
                  rhsa_imp=_list_uns_by_sev("important"),
                  timestamp=fleure.globals.TODAY)

    return dict(name="rpm_depgraph_1",
                layers=sorted(list(groups.keys()) + ["visible"]),
                nodes=sorted(_mk_ps_g(graph, groups),
                             key=operator.itemgetter("name")),
                edges=sorted(graph.edges_iter()))


def dump_depgraph(root, ers, workdir=None, outname="rpm_depgraph_gv",
                  tpaths=fleure.globals.FLEURE_TEMPLATE_PATHS):
    """
    Make up context to generate RPM dependency graph w/ graphviz (sfdp) from
    the RPM database files for given host group.

    :param root: Host group's root dir where 'var/lib/rpm' exists
    :param ers: List of errata dict, see :func:`analyze_errata` in fleure.main
    :param workdir: Working dir to dump result
    :param outname: Output file base name
    :param tpaths: A list of template search paths
    """
    if workdir is None:
        workdir = root

    ctx = _make_depgraph_context(root, ers)
    fleure.utils.json_dump(ctx, os.path.join(workdir, outname + ".json"))

    output = os.path.join(workdir, outname + ".dot")
    opts = dict(at_paths=tpaths, at_engine="jinja2", at_ask_missing=True)
    anytemplate.render_to("rpm_depgraph_gv.dot.j2", ctx, output, **opts)
    anytemplate.render_to("rpm_depgraph_gv.css.j2", ctx,
                          os.path.join(workdir, outname + ".css"),
                          **opts)
    anytemplate.render_to("rpm_depgraph.html.j2", ctx,
                          os.path.join(workdir, "rpm_depgraph.html"), **opts)

    output2 = os.path.join(workdir, outname + ".svg")
    cmd_s = "sfdp -Tsvg -o%s %s" % (output2, output)
    (rcode, out, err) = fleure.utils.subproc_call(cmd_s, timeout=120)
    if rcode != 0:
        if not err:
            err = "Maybe timeout occurs"
        LOG.warning(_("Failed to generate a SVG file: in=%s, out=%s, "
                      "out/err=%s/%s"), output, output2, out, err)

# vim:sw=4:ts=4:et:
