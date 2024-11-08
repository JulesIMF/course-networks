#!/usr/bin/env bash
set -xeuo pipefail

pytest -v -x protocol_test.py -o log_cli=true --durations=0
