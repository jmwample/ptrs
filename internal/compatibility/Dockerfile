
FROM golang:bullseye as go-builder
WORKDIR /usr/src/obfs4-go
COPY internal/compatibility/obfs4/ .
RUN ls
RUN go mod tidy
RUN go build -o fwd_go .

FROM rust:bullseye as rs-builder
WORKDIR /usr/src/fwd
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates/
RUN cargo update
RUN cd crates/lyrebird && cargo install --path . --force --debug

FROM debian:bullseye-slim
RUN apt update && apt install -yq python3;
COPY --from=rs-builder /usr/local/cargo/bin/fwd /usr/local/bin/fwd_rs
COPY --from=go-builder /usr/src/obfs4-go/fwd_go /usr/local/bin/fwd_go
COPY internal/compatibility/ell2_bug_check/obfs4-* /usr/bin/
CMD ["fwd_rs"]
