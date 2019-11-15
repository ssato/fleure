#
# Copyright (C) 2015 Satoru SATOH <ssato@redhat.com>
# License: MIT
#
"""profiling fleure with line_profiler and memory_profiler.
"""
from __future__ import absolute_import, print_function

import argparse
import os.path
import os
import sys
import tempfile

try:
    import line_profiler
except ImportError:
    line_profiler = None

import fleure.analysis
import fleure.datasets
import fleure.main


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TARGETS = (fleure.main.main,
           # fleure.main.analyze_and_save_results,
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


def prof_main(argv=None):
    """main.
    """
    if argv is None:
        argv = sys.argv[1:]

    psr = argparse.ArgumentParser()
    psr.add_argument("-P", "--profile", choices=("line", "memory", "all"),
                     default="line")
    psr.add_argument("-w", "--workdir", help="Working dir to save results")
    args = psr.parse_args(argv)

    if args.workdir:
        workdir = args.workdir
    else:
        workdir = tempfile.mkdtemp(dir="/tmp", prefix="fleure-tests-")

    root_or_arc_path = os.path.join(os.path.dirname(__file__),
                                    "rhel-6-client-1_var_lib_rpm.tar.xz")
    cnf = dict(workdir=workdir, repos=["rhel-6-server-rpms"], verbosity=2,
               period=["2015-01-01", "2016-04-10"], archive=True)

    if args.profile in ("line", "all") and line_profiler:
        lprof = line_profiler.LineProfiler(*TARGETS)
        lprof.runcall(fleure.main.main, root_or_arc_path, **cnf)
        lprof.print_stats()
        lprof.dump_stats(os.path.join(workdir, "test.prof"))

    if args.profile in ("memory", "all"):
        print("Not implemented yet")
        sys.exit(0)

        for fun in TARGETS:
            # fun = memory_profiler.profile(fun)
            print("Wrapped: %s" % str(fun))

        fleure.main.main(root_or_arc_path, **cnf)
        # mprof = memory_profiler.LineProfiler(...)
        # mprof.print_stats()
        # mprof.dump_stats(os.path.join(workdir, "test.prof"))


if __name__ == '__main__':
    prof_main()

# vim:sw=4:ts=4:et:
