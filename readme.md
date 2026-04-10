# BIP39 Tool

A tool for converting BIP39 mnemonic phrases to addresses and private keys.

## Neurai Network Parameters

Neurai uses specific parameters for its chain and Post-Quantum (PQ) cryptography features.

* **Coin Name**: Neurai
* **Ticker**: XNA
* **BIP44 Coin Type**: `1900`
* **Legacy Derivation Path**: `m/44'/1900'/0'/0`
* **Testnet Legacy Derivation Path**: `m/44'/1'/0'/0`

### Post-Quantum Cryptography (PQ)

Neurai integrates Post-Quantum cryptography for enhanced security.

* **Algorithm**: ML-DSA-44 (Dilithium2)
* **PQ Derivation Path**: `m/100'/1900'/0'/0`
* **PQ Testnet Derivation Path**: `m/100'/1'/0'/0`
* **Address Format**: Addresses starting with `nq1...` (Bech32)

## Online Version

https://bip39.neurai.org

## Standalone offline version

Download `bip39-standalone.html` from
[Neurai Releses](https://github.com/NeuraiProject/bip39/releases).

Open the file in a browser by double clicking it.

This can be compiled from source using the command `python compile.py`

## Usage

Enter your BIP39 phrase into the 'BIP39 Phrase' field, or press
'Generate Random Phrase'

If required, set the derivation path, although the defaults are quite usable.

See the table for a list of addresses generated from the phrase.

Toggle columns to blank to easily copy/paste a single column of data, eg to
import private keys into a wallet or supply someone with a list of addresses.

The BIP32 keys can be used at [bip32.org](https://bip32.org) if desired.

## Making changes

Please do not make modifications to `bip39-standalone.html`, since they will
be overwritten by `compile.py`.

Make changes in `src/*`.

Changes are applied during release using the command `python compile.py`, so
please do not commit changes to `bip39-standalone.html`

# Tests

Tests depend on

* nodejs
* selenium webdriver - cd /path/to/bip39/tests; npm install
* selenium driver for firefox ([geckodriver](https://github.com/mozilla/geckodriver/releases)) and / or chrome ([chromedriver](https://sites.google.com/a/chromium.org/chromedriver/downloads))
* jasmine - npm install --global jasmine

Before running tests, the site must be served at http://localhost:8000.

```
$ cd /path/to/bip39/src
$ python -m http.server

or for python2
$ python -m SimpleHTTPServer
```

Run tests from the command-line

```
$ cd /path/to/bip39/tests
$ jasmine spec/tests.js
```

# License

This BIP39 tool is released under the terms of the MIT license. See LICENSE for
more information or see https://opensource.org/licenses/MIT.
