"""Burp Suite -> blindsqli exporter.

`core` holds all pure logic (request parsing, parameter enumeration, config
serialization/merge) and has no Burp dependency, so it runs under both Jython
(inside Burp) and CPython 3 (for the tests). `extension` is the thin Burp/Jython
UI shim that calls into `core`.
"""
