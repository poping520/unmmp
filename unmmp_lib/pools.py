# -*- coding: utf-8 -*-
"""Symbol references resolved by one target-native VM resolver."""


class Pools:
    def __init__(self):
        self.types = []
        self.const_strings = []
        self.fields = []
        self.methods = []
        self.semantic_aliases = {}
