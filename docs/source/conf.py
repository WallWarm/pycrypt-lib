# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import os
import sys

sys.path.insert(0, os.path.abspath("../../src/"))

project = "pycrypt"
copyright = "2025, Aravindaksha Balaji"
author = "Aravindaksha Balaji"
release = "1.0.4"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.autosummary",
    "sphinx_rtd_theme",
]

templates_path = ["_templates"]
exclude_patterns = []

autosummary_generate = True
autoclass_content = "class"

autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "inherited-members": True,
    "show-inheritance": True,
}
autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_class_signature = "mixed"
autodoc_dataclass_show_fields = True
autodoc_dataclass_signature = "mixed"
autodoc_inherit_docstrings = True

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

html_context = {
    "display_github": True,
    "github_user": "aravindakshabalaji",
    "github_repo": "pycrypt-lib",
    "github_version": "main/docs/source/",
}
