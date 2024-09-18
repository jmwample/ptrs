
docker:
	docker build -t obfs4-compat -f internal/compatibility/Dockerfile .


release:
	cargo build --release

msrv:
	cargo +1.70 test -p ptrs --all-targets --all-features
	cargo +1.75 test --workspace --all-targets --all-features

