# syntax=docker/dockerfile:1
FROM rust:1-slim-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang make perl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Cache dependencies separately from our sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src target/release/deps/sshmux_mcp*
COPY src ./src
# Unit tests gate the image: a failing test fails the build (and the weekly update).
RUN cargo test --release && cargo build --release

FROM debian:trixie-slim
COPY --from=build /src/target/release/sshmux-mcp /usr/local/bin/sshmux-mcp
USER 1000:1000
ENV SSH_MCP_LISTEN=0.0.0.0:8011 RUST_LOG=info,russh=warn
EXPOSE 8011
HEALTHCHECK --interval=30s --timeout=3s CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8011"]
ENTRYPOINT ["/usr/local/bin/sshmux-mcp"]
CMD ["/config/container.toml"]
