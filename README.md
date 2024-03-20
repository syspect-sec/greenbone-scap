![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# greenbone-scap - Python library for downloading CVE and CPE from NIST NVD  <!-- omit in toc -->

[![GitHub releases](https://img.shields.io/github/release/greenbone/greenbone-scap.svg)](https://github.com/greenbone/greenbone-scap/releases)
[![PyPI release](https://img.shields.io/pypi/v/greenbone-scap.svg)](https://pypi.org/project/greenbone-scap/)
[![Build and test](https://github.com/greenbone/greenbone-scap/actions/workflows/ci-python.yml/badge.svg)](https://github.com/greenbone/greenbone-scap/actions/workflows/ci-python.yml)

The **greenbone-scap** Python package is a collection of utilities and tools to
download the CPE and CVE information from the [NIST NVD REST API](https://nvd.nist.gov/developers)
into a PostgreSQL database.

## Table of Contents <!-- omit in toc -->

- [Installation](#installation)
  - [Requirements](#requirements)
  - [Install using pipx](#install-using-pipx)
  - [Install using pip](#install-using-pip)
- [Command Completion](#command-completion)
  - [Setup for bash](#setup-for-bash)
  - [Setup for zsh](#setup-for-zsh)
- [Development](#development)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Requirements

Python 3.11 and later is supported.

### Install using pipx

You can install the latest stable release of **greenbone-scap** from the [Python
Package Index (pypi)][pypi] using [pipx]

    python3 -m pipx install greenbone-scap

### Install using pip

> [!NOTE]
> The `pip install` command does no longer work out-of-the-box in newer
> distributions like Ubuntu 23.04 because of [PEP 668](https://peps.python.org/pep-0668).
> Please use the [installation via pipx](#install-using-pipx) instead.

You can install the latest stable release of **greenbone-scap** from the [Python
Package Index (pypi)][pypi] using [pip]

    python3 -m pip install --user greenbone-scap

## Command Completion

`greenbone-scap` comes with support for command line completion in bash and zsh.
All greenbone-scap CLI commands support shell completion. As examples the
following sections explain how to set up the completion for `greenbone-cve-download`
with bash and zsh.

### Setup for bash

```bash
echo "source ~/.greenbone-cve-download-complete.bash" >> ~/.bashrc
greenbone-cve-download --print-completion bash > ~/.greenbone-cve-download-complete.bash
```

Alternatively, you can use the result of the completion command directly with
the eval function of your bash shell:

```bash
eval "$(greenbone-cve-download --print-completion bash)"
```

### Setup for zsh

```zsh
echo 'fpath=("$HOME/.zsh.d" $fpath)' >> ~/.zsh
mkdir -p ~/.zsh.d/
greenbone-cve-download --print-completion zsh > ~/.zsh.d/_greenbone_cve_download
```

Alternatively, you can use the result of the completion command directly with
the eval function of your zsh shell:

```bash
eval "$(greenbone-cve-download --print-completion zsh)"
```

## Development

**greenbone-scap** uses [poetry] for its own dependency management and build
process.

First install poetry via [pipx]

    python3 -m pipx install poetry

Afterwards run

    poetry install

in the checkout directory of **greenbone-scap** (the directory containing the
`pyproject.toml` file) to install all dependencies including the packages only
required for development.

Afterwards activate the git hooks for auto-formatting and linting via
[autohooks].

    poetry run autohooks activate

Validate the activated git hooks by running

    poetry run autohooks check


## Maintainer

This project is maintained by [Greenbone AG][Greenbone]

## Contributing

Your contributions are highly appreciated. Please
[create a pull request](https://github.com/greenbone/greenbone-scap/pulls)
on GitHub. Bigger changes need to be discussed with the development team via the
[issues section at GitHub](https://github.com/greenbone/greenbone-scap/issues)
first.

## License

Copyright (C) 2024 [Greenbone AG][Greenbone]

Licensed under the [GNU General Public License v3.0 or later](LICENSE).

[Greenbone]: https://www.greenbone.net/
[poetry]: https://python-poetry.org/
[pip]: https://pip.pypa.io/
[pipx]: https://pypa.github.io/pipx/
[autohooks]: https://github.com/greenbone/autohooks
[pypi]: https://pypi.org
