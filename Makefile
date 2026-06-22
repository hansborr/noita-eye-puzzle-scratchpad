# Developer guardrail commands. Run `make check` (or `make verify`) before a commit.
# CI (.github/workflows/ci.yml) runs the same checks plus the release build.

.PHONY: check verify fmt fmt-check lint test doc-check deny machete spell build setup run clean

## check: full local CI — verify + unused-deps + spelling + release build
check: verify machete spell build

## verify: the correctness gate the pre-commit hook runs
verify: fmt-check lint test doc-check deny

## fmt: apply rustfmt
fmt:
	cargo fmt

## fmt-check: verify formatting without changing files
fmt-check:
	cargo fmt --check

## lint: clippy with warnings treated as errors
lint:
	cargo clippy --all-targets --all-features --locked -- -D warnings

## test: run tests, failing on any compiler warning
test:
	RUSTFLAGS="-D warnings" cargo test --locked

## doc-check: build docs, failing on any rustdoc warning
doc-check:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked

## deny: cargo-deny supply-chain checks (advisories, licenses, bans, sources)
deny:
	cargo deny check

## machete: detect unused dependencies
machete:
	cargo machete --with-metadata

## spell: spell-check sources and docs (config in .codespellrc)
spell:
	codespell

## build: optimized release build
build:
	cargo build --release --locked

## setup: install the git pre-commit hook
setup:
	git config core.hooksPath .githooks
	@echo "pre-commit hook installed (core.hooksPath = .githooks)"

## run: run the CLI, e.g. `make run ARGS=demo`
run:
	cargo run -- $(ARGS)

## clean: remove build artifacts
clean:
	cargo clean
