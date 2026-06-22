# Developer guardrail commands. Run `make check` before every commit.
# (CI runs the same steps — see .github/workflows/ci.yml.)

.PHONY: check fmt fmt-check lint test build run clean

## check: format check + clippy (deny warnings) + tests + release build
check: fmt-check lint test build

## fmt: apply rustfmt
fmt:
	cargo fmt

## fmt-check: verify formatting without changing files
fmt-check:
	cargo fmt --check

## lint: clippy with warnings treated as errors
lint:
	cargo clippy --all-targets --all-features -- -D warnings

## test: run the test suite
test:
	cargo test

## build: optimized release build
build:
	cargo build --release

## run: run the CLI, e.g. `make run ARGS=demo`
run:
	cargo run -- $(ARGS)

## clean: remove build artifacts
clean:
	cargo clean
