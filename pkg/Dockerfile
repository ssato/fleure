# FROM ssato/python-dev:latest
FROM fedora:latest
MAINTAINER https://github.com/ssato/fleure

# It will take some time to finish.
# RUN dnf -y update && dnf clean all

# see pkg/requirements.txt, pkg/test_requirements.txt and pkg/package.spec.in
RUN dnf install -y dnf-plugins-core && dnf copr enable -y ssato/python-anyconfig
RUN dnf install -y git python3-any{config,template} \
python3-{beautifulsoup4,networkx,nltk,tablib,line_profiler,sqlalchemy,ipython} \
python3-{dnf,nltk,beautifulsoup4,matplotlib,networkx,tablib,line_profiler,sqlalchemy,ipython} \
python3-{flake8,pylint,nose}

ARG branch=master
RUN git clone https://github.com/ssato/fleure.git -b ${branch} /tmp/fleure
RUN mkdir -p /usr/share/nltk_data && python3 -m nltk.downloader punkt
CMD cd /tmp/fleure && bash -x ./pkg/runtest.sh
