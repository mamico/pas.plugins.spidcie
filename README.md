<div align="center"><img alt="pas.plugins.spidcie logo" src="https://raw.githubusercontent.com/collective/pas.plugins.spidcie/main/docs/icon.png" width="70" /></div>

<h1 align="center">pas.plugins.spidcie</h1>

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/pas.plugins.spidcie)](https://pypi.org/project/pas.plugins.spidcie/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pas.plugins.spidcie)](https://pypi.org/project/pas.plugins.spidcie/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/pas.plugins.spidcie)](https://pypi.org/project/pas.plugins.spidcie/)
[![PyPI - License](https://img.shields.io/pypi/l/pas.plugins.spidcie)](https://pypi.org/project/pas.plugins.spidcie/)
[![PyPI - Status](https://img.shields.io/pypi/status/pas.plugins.spidcie)](https://pypi.org/project/pas.plugins.spidcie/)


[![PyPI - Plone Versions](https://img.shields.io/pypi/frameworkversions/plone/pas.plugins.spidcie)](https://pypi.org/project/pas.plugins.spidcie/)

[![Meta](https://github.com/collective/pas.plugins.spidcie/actions/workflows/meta.yml/badge.svg)](https://github.com/collective/pas.plugins.spidcie/actions/workflows/meta.yml)
![Code Style](https://img.shields.io/badge/Code%20Style-Black-000000)

[![GitHub contributors](https://img.shields.io/github/contributors/collective/pas.plugins.spidcie)](https://github.com/collective/pas.plugins.spidcie)
[![GitHub Repo stars](https://img.shields.io/github/stars/collective/pas.plugins.spidcie?style=social)](https://github.com/collective/pas.plugins.spidcie)

</div>

## Intro
This is a Plone authentication plugin for SPID/CIE, OpenID Connect Federation.

## Features

- PAS plugin, although currently no interfaces are activated.
- Three browser views for this PAS plugin, which are the main interaction with the outside world.


## Installation

This package supports Plone sites using Volto and ClassicUI.

For proper Volto support, the requirements are:

* plone.restapi >= 8.34.0
* Volto >= 16.10.0

Add **pas.plugins.spidcie** to the Plone installation using `pip`:

``bash
pip install pas.plugins.spidcie
``

## Configure the plugin

* Go to the Add-ons control panel and install `pas.plugins.spidcie`.
* In the ZMI go to the plugin properties at `http://localhost:8080/Plone/acl_users/oidc/manage_propertiesForm`

### Trust marks

The `trust_marks` property is refreshed automatically from the federation
registry's `/resolve` endpoint and should not normally need manual editing;
it's kept as a fallback for when the registry can't be reached.

If you do need to set it by hand, get the value from `/resolve`
(`https://<anchor>/resolve?sub=<client_id>&anchor=<anchor>`), **not** from
what the federation portal's UI shows you. The two can differ significantly:
on one site the portal displayed a trust mark with only a few hours left
before expiry, while `/resolve` returned one valid for several more months.
Copying the portal's value gives the RP a trust mark that looks fine at
setup time and then expires far sooner than expected.


## License

The project is licensed under the GPLv2.
