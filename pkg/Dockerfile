FROM fedora:22
MAINTAINER https://github.com/ssato/fleure

# It will take some time to finish.
# RUN dnf -y update && dnf clean all

# see pkg/requirements.txt, pkg/test_requirements.txt and pkg/package.spec.in
RUN dnf install -y dnf-plugins-core && dnf copr enable -y ssato/python-anyconfig
RUN dnf install -y findutils git tar zip pylint python-anyconfig \
python-{pip,nltk,beautifulsoup4,bunch,matplotlib,networkx,tablib,flake8,nose,pep8}
RUN pip install anytemplate coveralls
RUN git clone https://github.com/ssato/fleure.git fleure.git && cd fleure.git

CMD bash -x ./pkg/runtest.sh
