FROM ekidd/rust-musl-builder as builder

WORKDIR /home/rust/

COPY Cargo.toml .
COPY Cargo.lock .

RUN echo "fn main() {}" > src/main.rs
RUN cargo test && cargo build --release

COPY . .
RUN sudo touch src/main.rs

RUN cargo test && cargo build --release

RUN strip /home/rust/target/x86_64-unknown-linux-musl/release/rcache-proxy

FROM alpine
WORKDIR /home/rust/
COPY --from=builder /home/rust/target/x86_64-unknown-linux-musl/release/rcache-proxy .
CMD ["./rcache-proxy"]
