"""Toolstack desktop shell: a thin native window around the admin control panel.

A deps-carrying component (like `admin`): it needs pywebview + the admin's runtime deps,
so it is NOT part of the stdlib `pyproject` packaging. Run it with `python3 -m desktop`.
See desktop/README.md.
"""
