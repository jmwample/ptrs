
docker:
	docker build -t obfs4-compat -f internal/compitability/obfs4/Dockerfile .


release:
	cargo build --release
