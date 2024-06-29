
docker:
	docker build -t obfs4-compat -f internal/compatibility/Dockerfile .


release:
	cargo build --release
