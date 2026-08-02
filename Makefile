.PHONY: build test test-rust test-python corpus bench lint clean

# The Python bindings dlopen the release library, so it has to exist and be
# current. Forgetting this is the one confusing failure mode of the harness:
# the tests run against a stale .dylib and disagree with the source.
build:
	cargo build --release

test: test-rust test-python

test-rust:
	cargo test --workspace

test-python: build
	.venv/bin/python -m pytest python/tests -q

venv:
	python3 -m venv .venv
	.venv/bin/pip install -q --upgrade pip
	.venv/bin/pip install -q pytest

corpus:
	cargo run -q --release -p shellguard-cli -- corpus

bench:
	cargo run -q --release -p shellguard-cli -- bench

lint:
	cargo fmt --check
	cargo clippy --all-targets
	cargo check -p shellguard-enforce --target x86_64-unknown-linux-gnu
	cargo check -p shellguard-enforce --target aarch64-unknown-linux-gnu

clean:
	cargo clean
	rm -rf .venv **/__pycache__ .pytest_cache
