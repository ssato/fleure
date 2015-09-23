#
# -*- coding: utf-8 -*-
# Copyright (C) 2015 Satoru SATOH <ssato@redhat.com>
# License: AGPLv3+
#
# References:
#   - http://flask.pocoo.org/docs/0.10/patterns/fileuploads/
#   - https://pythonhosted.org/Flask-Uploads/
'''Fleure's Web UI module
'''
from __future__ import absolute_import

import flask
import os.path
import werkzeug


# TBD:
UPLOAD_FOLDER = '/tmp/uploads'  # TBD
ALLOWED_EXTENSIONS = ('.zip', '.tar.xz')
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # [MB]


app = flask.Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


def allowed_file(filename, exts=ALLOWED_EXTENSIONS):
    '''
    :param filename: Name of the file to upload
    :param exts: A list of file extensions allowed to upload
    '''
    return '.' in filename and any(filename.endswith(x) for x in exts)


@app.route('/', methods=('GET', 'POST'))
def upload_file():
    """
    Upload page
    """
    if flask.request.method == 'POST':
        file = flask.request.files['file']
        if file and allowed_file(file.filename):
            filename = werkzeug.secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return flask.redirect(flask.url_for('fileinfo', filename=filename))

    return flask.render_template('upload.html', filename='<not choosen>')


@app.route('/uploads/<filename>')
def fileinfo(filename):
    """
    Show basic info of uploaded files.
    """
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    filesize = os.path.getsize(filepath) / 1024
    return flask.render_template('fileinfo.html', filename=filename,
                                 filesize=filesize)


@app.route('/download/<filename>')
def download_uploaded_file(filename):
    """
    Download uploaded files.
    """
    return flask.send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0')

# vim:sw=4:ts=4:et:
