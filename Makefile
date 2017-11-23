all:
	@cargo build
	@cargo test
	@cargo doc --no-deps
	@cargo build --all-features
	@cargo test --all-features
	@cargo doc --all-features --no-deps
	@cargo fmt --all
	@cargo clippy -- -A blacklisted-name -A unreadable-literal -D warnings --all
