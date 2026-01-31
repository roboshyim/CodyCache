# Build stage
FROM rust:1.75-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs
RUN cargo build --release || true
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/codycache /usr/local/bin/codycache
EXPOSE 8080
ENV RUST_LOG=info
CMD ["/usr/local/bin/codycache"]
