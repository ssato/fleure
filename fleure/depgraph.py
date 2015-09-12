#
# Copyright (C) 2013 - 2015 Red Hat, Inc.
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

import networkx
import os.path
import yum  # TODO: Remove dependency to yum and switch to dnf.


_E_ATTRS = dict(weight=1.0, )


def yum_list_installed(root=None, cachedir=None, persistdir=None):
    """
    List installed packages using an internal API of yum.

    :param root: RPM DB root dir
    :return: List of yum.rpmsack.RPMInstalledPackage objects
    """
    if root is None:
        root = "/var/lib/rpm"

    if persistdir is None:
        persistdir = root

    cachedir = os.path.join(root, "cache")
    sack = yum.rpmsack.RPMDBPackageSack(root, cachedir=cachedir,
                                        persistdir=persistdir)
    return sack.returnPackages()  # NOTE: 'gpg-pubkey' is not in this list.


def make_requires_dict(root=None, reverse=False, use_yum=True):
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

    assert use_yum, "Not implemented w/o yum yet!"  # Not yet.

    list_installed = yum_list_installed  # Alternative is not available yet.
    return dict((p.name, list_reqs(p)) for p in list_installed(root))


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
    for key, vals in rreqs.iteritems():
        graph.add_node(key, names=[key])
        graph.add_edges_from([(key, val, edge_attrs) for val in vals])

    # Remove edges of self cyclic nodes:
    graph.remove_edges_from(graph.selfloop_edges())

    return graph


# vim:sw=4:ts=4:et:
