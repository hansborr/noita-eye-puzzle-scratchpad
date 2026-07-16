#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"

output="$("$repo_root/scripts/cubemorse_reference.py" \
    --null-trials 8 \
    "$repo_root/research/data/practice-puzzles/six")"

[[ "$output" == *"cubemorse Python reference self-test: PASS"* ]]
[[ "$output" == *"'CUBE IS A GREAT TOY MODEL OF NON-COMMUTATIVITY.' RoundTrip exact"* ]]
[[ "$output" == *"'FUBE IS A GREAT TOY MODEL OF NON-COMMUTATIVITY.' RoundTrip exact"* ]]
[[ "$output" == *"matched null survivors: 0/8"* ]]

printf 'ok - cubemorse Python reference\n'
