# Third-party notices

Harpo is licensed under the Apache License 2.0. It uses the components below under their own licences.
Generated from installed package metadata (`python tools/third_party.py`); check the packages themselves for full texts.

## Bundled in the repository or the console

| Component | Licence |
| --- | --- |
| Geist and Geist Mono fonts (console) | SIL Open Font License 1.1 (`console/fonts/LICENSE-geist.txt`) |
| Lucide icons (console) | ISC |
| gitleaks detection rules (secret library) | MIT |
| BIP39 English wordlist (from trezor/python-mnemonic) | MIT |

## spaCy models

| Model | Licence | In the default Docker image |
| --- | --- | --- |
| en_core_web_sm (English) | MIT | yes |
| de_core_news_sm (German) | MIT | yes |
| xx_ent_wiki_sm (multilingual fallback) | MIT | yes |
| nl_core_news_sm (Dutch) | CC BY-SA 4.0 | no, opt-in |
| fr_core_news_sm (French) | LGPL-LR | no, opt-in |
| es_core_news_sm (Spanish) | GNU GPL 3.0 | no, opt-in |

The opt-in models are installed with `docker build --build-arg EXTRA_NER_MODELS="nl fr es"` or `pip install`. If you
distribute an image or product that contains them, their licences apply to that distribution: check them first.

## Python dependencies (requirements.lock)

| Package | Licence |
| --- | --- |
| annotated-doc | MIT |
| annotated-types | MIT |
| anyio | MIT |
| blis | BSD |
| catalogue | MIT |
| certifi | MPL-2.0 |
| charset-normalizer | MIT |
| click | BSD-3-Clause |
| cloudpathlib | MIT License |
| confection | MIT |
| cymem | MIT |
| fastapi | MIT |
| google-re2 | BSD License |
| h11 | MIT |
| httpcore | BSD-3-Clause |
| httptools | MIT |
| httpx | BSD-3-Clause |
| idna | BSD-3-Clause |
| jinja2 | BSD License |
| lxml | BSD-3-Clause |
| markdown-it-py | MIT License |
| markupsafe | BSD-3-Clause |
| mdurl | MIT License |
| murmurhash | MIT |
| numpy | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| opentelemetry-api | Apache-2.0 |
| packaging | Apache-2.0 OR BSD-2-Clause |
| phonenumbers | Apache-2.0 |
| pillow | MIT-CMU |
| preshed | MIT |
| prometheus-client | Apache-2.0 AND BSD-2-Clause |
| pydantic | MIT |
| pydantic-core | MIT |
| pydantic-settings | MIT |
| pygments | BSD-2-Clause |
| pypdfium2 | BSD-3-Clause, Apache-2.0, dependency licenses |
| python-dotenv | BSD-3-Clause |
| python-stdnum | LGPL |
| pyyaml | MIT |
| requests | Apache-2.0 |
| rich | MIT |
| setuptools | MIT |
| shellingham | ISC License |
| smart-open | MIT License |
| spacy | MIT |
| spacy-legacy | MIT |
| spacy-loggers | MIT |
| srsly | MIT |
| starlette | BSD-3-Clause |
| thinc | MIT |
| tqdm | MPL-2.0 AND MIT |
| typer | MIT |
| typing-extensions | PSF-2.0 |
| typing-inspection | MIT |
| urllib3 | MIT |
| uvicorn | BSD-3-Clause |
| uvloop | MIT License |
| wasabi | MIT |
| watchfiles | MIT |
| weasel | MIT |
| websockets | BSD-3-Clause |
| wrapt | BSD-2-Clause |
