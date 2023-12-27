#!/usr/bin/env python3

import sys

# MutableMapping moved
if sys.version_info[:2] >= (3, 8):
    from collections.abc import MutableMapping
else:
    from collections import MutableMapping

try:
    from itertools import imap
except ImportError:
    # Python 3...
    imap=map


class KeyAdjustedOffsetMapping(MutableMapping):
    """MutableMapping where changes in child mappings are
    visible in parent, but changes in parent are not visible in child"""
    def __init__(self, offset=0, parent=None):
        self.parent = parent
        self.map = {}
        self.descendants = []
        self.offset = offset
        self.adjustment_to_parent = 0
        if self.parent is not None:
            self.adjustment_to_parent = self.offset

    def new_child(self, offset):
        chld = self.__class__(offset, parent=self)
        return chld

    @property
    def root(self):
        """return highest level ancestor"""
        return self if self.parent is None else self.parent.root

    def __getitem__(self, key):
        return self.map[key]

    def __setitem__(self, key, value):
        self.map[key] = value
        if self.parent is None:
            return
        self.parent[key+self.adjustment_to_parent] = value

    def __delitem__(self, key):
        del self.map[key]
        if self.parent is None:
            return
        del self.parent.map[key]

    def __len__(self):
        return len(self.map)

    def __iter__(self):
        return iter(self.map)

    def __contains__(self, key):
        return key in self.map

    def __repr__(self):
        return repr(self.map)


if __name__ == "__main__":
    a = KeyAdjustedOffsetMapping()
    a[0] = 'a'

    b = a.new_child(4)
    b[0] = 'b'

    c = b.new_child(8)
    c[4] = 'c'

