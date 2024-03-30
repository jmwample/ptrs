
docker:
	docker build -t obfs4-compat -f internal/compatability/obfs4/Dockerfile .


release:
	cargo build --release
