# Changelog

<!--
   You should *NOT* be adding new change log entries to this file.
   You should create a file in the news directory instead.
   For helpful instructions, please see:
   https://github.com/plone/plone.releaser/blob/master/ADD-A-NEWS-ITEM.rst
-->

<!-- towncrier release notes start -->

## 2.0.0a3 (2026-09-01)


### New features:

- Added Deutsch translation
  [@macagua] [#45](https://github.com/collective/pas.plugins.spidcie/issues/45)
- Add a standalone SAST workflow (`.github/workflows/sast.yml`) running `ruff check --select S` (the flake8-bandit rules ported to ruff), replacing the bandit hook removed earlier. Fixed the findings it surfaced: missing `timeout` on the token/userinfo/federation HTTP requests, and ported the existing `try`/`except`/`pass` suppression from bandit's `# nosec` to ruff's `# noqa` syntax [mamico] [#49](https://github.com/collective/pas.plugins.spidcie/issues/49)


### Bug fixes:

- Fix unbounded ZODB growth of the OIDC session store: switch it from `PersistentMapping` to `OOBTree` so each login only rewrites its own entry instead of the whole store, stop duplicating the OP's full provider configuration in every entry, and pop (instead of get) the entry at the callback so a consumed authorization state is removed and cannot be replayed [mamico] [#46](https://github.com/collective/pas.plugins.spidcie/issues/46)


### Internal:

- Remove bandit from pre-commit/CI: its hook environment is broken (`ModuleNotFoundError: No module named 'pbr'` when bandit starts). SAST is to be reinstated with ruff [mamico] [#47](https://github.com/collective/pas.plugins.spidcie/issues/47)
- Fix the qa/dependencies/release_ready CI checks, exercised here for the first time (first PR ever opened on this fork): apply pending pyupgrade/isort/black/zpretty formatting, drop unused imports, fix typos, extend the check-manifest ignore list, pin `setuptools<80` for the dependencychecker env (its pinned `z3c.dependencychecker==2.11` needs `pkg_resources`, removed from later setuptools), declare `requests`/`cryptography` as direct install requirements, and stop the release-check env from picking up Plone's own release constraints (which pin a twine/pkginfo too old to read the sdist metadata `python -m build` now produces) [mamico] [#48](https://github.com/collective/pas.plugins.spidcie/issues/48)

## 2.0.0a3 (unreleased)


- Nothing changed yet.


## 2.0.0a1 (2023-11-23)


### New features:

- Implement [plone/meta](https://github.com/plone/meta) and convert documentation to Markdown [@ericof] [#32](https://github.com/collective/pas.plugins.spidcie/issues/32)
- Drop support to Python 2.7 and Plone 5.2 [@ericof] [#33](https://github.com/collective/pas.plugins.spidcie/issues/33)
- Implement restapi services to handle authentication flow [@ericof] [#38](https://github.com/collective/pas.plugins.spidcie/issues/38)


### Internal:

- Rewrite tests from unittest to pytest with [pytest-plone](https://pypi.org/project/pytest-plone/) [@ericof] [#34](https://github.com/collective/pas.plugins.spidcie/issues/34)
- Allow dict instances to hold userinfo [@erral] [#35](https://github.com/collective/pas.plugins.spidcie/issues/35)
- Declare the minimum requirements for Plone/python in the readme [mamico] [#36](https://github.com/collective/pas.plugins.spidcie/issues/36)


## 1.0.0 (2023-11-11)

- Allow dict instances to hold userinfo [@erral]

## 1.0a6 (2023-07-20)

- Added Spanish translation [@macagua]

- Added improvements about i18n support [macagua]

- Drop python 2.7 and Plone 4 support [@erral]

- Add support for the post_logout parameter for logout api. [@ramiroluz]


## 1.0a5 (2023-04-05)

- Catch exceptions during the OAuth process [@erral]

- Update the plugin to make challenges.
  An anonymous user who visits a page for which you have to be authenticated,
  is redirected to the new require_login view on the plugin.
  This works the same way as the standard require_login page of Plone.
  [@maurits]

- Add a property for the default userinfo instead of using only sub. [@eikichi18]


## 1.0a4 (2023-01-16)

- Call getProperty only once when getting redirect_uris or scope. [@maurits]

- use getProperty accessor [@mamico]


## 1.0a3 (2022-10-30)

- Removed the hardcoded auth cookie name [@alecghica]

- Fixed Python compatibility with version >= 3.6 [@alecghica]

- check if url is in portal before redirect #2 [@erral]

- manage came_from [@mamico]

## 1.0a2 (unreleased)

- do userinforequest if there is a client.userinfo_endpoint [@mamico]

## 1.0a1 (unreleased)

- Initial release. [@mamico]
