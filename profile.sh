#!/bin/bash

export CARGO_PROFILE_RELEASE_DEBUG=true
rm -f minivault.sock
rm -rf cargo-flamegraph.trace
cargo flamegraph -o flamegraph.svg -- run -v test.yml
