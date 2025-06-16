# -*- coding: utf-8 -*-
"""
Define a YAML simple class for including another .yaml file into .yaml file and add a constructor
for it.

Taken from https://stackoverflow.com/questions/528281/how-can-i-include-a-yaml-file-inside-another
"""
import os
import yaml

class Loader(yaml.SafeLoader): # pylint: disable=too-many-ancestors
    """
    A simple class utilising the PyYaml SafeLoader class to add the capability of including a .yaml
    file into .yaml file.
    """
    def __init__(self, stream):

        self._root = os.path.split(stream.name)[0]
        super().__init__(stream)

    def include(self, node):
        """
        The method to include .yaml file.
        """
        filename = os.path.join(self._root, self.construct_scalar(node))

        with open(filename, 'r', encoding='utf-8') as f:
            return yaml.load(f, Loader)
