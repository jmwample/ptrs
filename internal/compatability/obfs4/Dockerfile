
FROM ghcr.io/rust-lang/rust:nightly-bullseye-slim as rs-builder
WORKDIR /usr/src/fwd_proxy
COPY . .
RUN apt-get update -y && apt-get install -y libgmp3-dev pkg-config
RUN cargo install --path . --bin fwd_proxy

FROM golang:bullseye as go-builder
WORKDIR /usr/src/obfs4-go
COPY internal/compatability/obfs4/ .
RUN ls
RUN go mod tidy
RUN go build -o fwd_go .

FROM debian:bullseye-slim
RUN apt-get update -y && apt-get install -y libgmp3-dev pkg-config
COPY --from=rs-builder /usr/local/cargo/bin/fwd_proxy /usr/local/bin/fwd_rs
COPY --from=go-builder /usr/src/obfs4-go/fwd_go /usr/local/bin/fwd_go
CMD ["fwd_rs"]
