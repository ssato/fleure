FROM ssato/python-dev:fedora-22
MAINTAINER https://github.com/ssato/fleure

# It will take some time to finish.
# RUN dnf -y update && dnf clean all

# see pkg/requirements.txt, pkg/test_requirements.txt and pkg/package.spec.in
RUN dnf install -y dnf-plugins-core && dnf copr enable -y ssato/python-anyconfig
RUN dnf install -y python-anyconfig python-{nltk,beautifulsoup4,bunch,matplotlib,networkx,tablib}
RUN pip install anytemplate

RUN git clone https://github.com/ssato/fleure.git /tmp/fleure
CMD cd /tmp/fleure && bash -x ./pkg/runtest.sh
