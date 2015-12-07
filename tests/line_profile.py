#
# Copyright (C) 2015 Satoru SATOH <ssato@redhat.com>
# License: MIT
#
"""fleure's CLI frontend.
"""
from __future__ import absolute_import

import line_profiler
import os.path
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.curdir, ".."))

import fleure.analysis
import fleure.datasets
import fleure.main


TARGETS = (fleure.main.main,
           fleure.main.dump_results,
           fleure.main.prepare,
           fleure.main.analyze,
           fleure.main.archive_report,
           fleure.analysis.list_latest_errata_by_updates,
           fleure.analysis.list_updates_from_errata,
           fleure.analysis.errata_of_keywords_g,
           fleure.analysis.list_update_errata_pairs,
           fleure.analysis.list_updates_by_num_of_errata,
           fleure.analysis.analyze_rhsa,
           fleure.analysis.analyze_rhba,
           fleure.analysis.analyze_errata,
           fleure.analysis.mk_overview_dataset,
           fleure.datasets.make_dataset)


def prof_main():
    """main.
    """
    tmpdir = tempfile.mkdtemp(dir="/tmp", prefix="fleure-tests-")
    root_or_arc_path = os.path.join(os.path.dirname(__file__),
                                    "rhel-6-client-1_var_lib_rpm.tar.xz")
    cnf = dict(workdir=tmpdir, repos=["rhel-6-server-rpms"], verbosity=2,
               period=["2015-01-01", "2015-11-11"], archive=True)

    prof = line_profiler.LineProfiler(*TARGETS)
    prof.runcall(fleure.main.main, root_or_arc_path, **cnf)
    prof.print_stats()
    prof.dump_stats(os.path.join(tmpdir, "test.prof"))


if __name__ == '__main__':
    prof_main()

# vim:sw=4:ts=4:et:
