# -*- coding: utf-8 -*-
"""
    sphinx.ext.todo
    ~~~~~~~~~~~~~~~

    Allow todos to be inserted into your documentation.  Inclusion of todos can
    be switched of by a configuration variable.  The todolist directive collects
    all todos of your project and lists them along with a backlink to the
    original location.

    :copyright: Copyright 2007-2009 by the Sphinx team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from docutils import nodes
import re, string
from sphinx.util.compat import Directive, make_admonition
from sphinx.directives import DescDirective, PythonDesc
from sphinx import addnodes

class CMake(PythonDesc):
    """
    Description of a cmake macro
    """

    def needs_arglist(self):
        return self.desctype == 'cmake'

    def get_index_text(self, modname, name_cls):
        return _('%s') % name_cls[0]

def setup(app):

    app.add_directive('cmake', CMake)


