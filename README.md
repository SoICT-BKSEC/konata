# kona

> **SoICT-BKSEC fork.** This is [project-sekai-ctf/konata](https://github.com/project-sekai-ctf/konata)
> with a provider for the BKSEC Training platform added. BKSEC Training is our
> re-development of [noCTF](https://github.com/noctf-project/noCTF). Changes from upstream:
>
> - `kona/external/bksectraining.py` — new: the provider. Configure it with a
>   `[bksectraining]` section in `kona.toml`.
> - `kona/schema/models.py` — `KonaBKSECTrainingCredentials`, the `bksectraining`
>   description template, and the `[bksectraining]` config section.
> - `kona/core/sync.py` — registers the provider.
> - `discovery.exclude` — folders discovery never enters, e.g. `exclude = ["archive"]`.
> - Removed upstream's PyPI release workflow and CODEOWNERS (they belong to upstream).
>
> Use it by checking out this repo and running `uv sync`; no patching step is needed.
> To take upstream changes: `git fetch upstream && git merge upstream/master`.

[![ci](https://github.com/project-sekai-ctf/konata/actions/workflows/lint_test.yml/badge.svg)](https://github.com/project-sekai-ctf/konata/actions/workflows/lint_test.yml)
[![pypi](https://img.shields.io/pypi/v/konata.svg)](https://pypi.python.org/project/konata)
[![license](https://img.shields.io/github/license/project-sekai-ctf/konata.svg)](https://github.com/project-sekai-ctf/konata/blob/master/LICENSE)

kona is a CTF tool for managing challenges and deploying them across multiple CTF platforms. It aims to fix the problems we have experienced while hosting CTFs.

Please see [rCTF docs](https://rctf.osec.io/integrations/konata/) for the documentation.

## Acknowledgements

* [rcds](https://github.com/redpwn/rcds) - inspiration
* [idekctf](https://github.com/idekctf) (JoshL & Trixter) - rCTF api reference, inspiration
* [ctfcli](https://github.com/ctfd/ctfcli) - CTFd api reference, inspiration
