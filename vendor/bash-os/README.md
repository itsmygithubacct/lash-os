# Vendored bash-os build inputs

Source: https://github.com/itsmygithubacct/bash-os

Revision: `fa178afafddfce8ee870975a38a7f271b25140a9`

This directory contains the source, build scripts, configuration, patches and
licenses needed by lashos. Upstream CI, benchmarks, development reports, examples
and test harnesses are omitted. Lashos maintains its regression suite in the
project-level `tests/` directory.

Build through the project-level Makefile. Native reference builds copy these
inputs into an external workspace before applying kernel adaptations.
See [license and provenance](docs/PROVENANCE.md) and [LICENSE](LICENSE).
