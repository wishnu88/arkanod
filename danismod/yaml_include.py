# -*- coding: utf-8 -*-
"""
Define a YAML simple class for including another .yaml file into .yaml file and add a constructor for it.

Taken from https://stackoverflow.com/questions/528281/how-can-i-include-a-yaml-file-inside-another
"""
import yaml
import os

class Loader(yaml.SafeLoader):

    def __init__(self, stream):

        self._root = os.path.split(stream.name)[0]

        super(Loader, self).__init__(stream)

    def include(self, node):

        filename = os.path.join(self._root, self.construct_scalar(node))

        with open(filename, 'r') as f:
            return yaml.load(f, Loader)

# Add the constructor to be used in yaml.load() function.
Loader.add_constructor('!include', Loader.include)