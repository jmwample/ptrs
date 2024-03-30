
FROM golang:bullseye as go-builder
WORKDIR /usr/src/obfs4-go
COPY internal/compatability/obfs4/ .
RUN ls
RUN go mod tidy
RUN go build -o fwd_go .

FROM rust:bullseye as rs-builder
WORKDIR /usr/src/fwd
COPY . .
RUN cargo update
RUN cd crates/pt-proxy && cargo install --path . --force

FROM debian:bullseye-slim
COPY --from=rs-builder /usr/local/cargo/bin/fwd /usr/local/bin/fwd_rs
COPY --from=go-builder /usr/src/obfs4-go/fwd_go /usr/local/bin/fwd_go
CMD ["fwd_rs"]
