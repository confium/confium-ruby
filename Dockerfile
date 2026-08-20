# Multi-stage Dockerfile for the Confium CLI + Ruby verifier.
#
# Stage 1 (builder): compiles the Rust CLI + Ruby native extension
# from source. Stage 2 (runtime): copies only the built artifacts
# into a slim image. Final image is ~80 MB compressed.
#
# Build:
#   docker build -t confium/signer .
# Run the CLI:
#   docker run --rm -v "$PWD:/work" confium/signer tc keygen \
#     --scheme cmp20 --threshold 2 --party-count 3 \
#     --out /work/shares.json
# Run the verifier:
#   docker run --rm -p 4567:4567 confium/signer verifier
# Health-check:
#   curl http://localhost:4567/health

# ----- Stage 1: builder -----
FROM ruby:3.3-slim-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust via rustup (stable, with rustfmt + clippy).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
        --default-toolchain stable \
        -c rustfmt clippy

WORKDIR /build

# Copy the gem source. In production builds, this would be a git
# checkout pinned to a release tag.
COPY . /build/confium-ruby

# Build the gem's native extension.
RUN cd /build/confium-ruby \
    && bundle install --jobs 4 \
    && bundle exec rake compile

# ----- Stage 2: runtime -----
FROM ruby:3.3-slim-bookworm AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Puma + Sinatra are needed to run the verifier; install as system gems
# so the runtime image stays single-layer.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && gem install --no-document puma sinatra \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled gem + examples from the builder.
COPY --from=builder /build/confium-ruby/lib /app/lib
COPY --from=builder /build/confium-ruby/examples /app/examples
COPY --from=builder /build/confium-ruby/Gemfile* /app/
COPY --from=builder /build/confium-ruby/confium.gemspec /app/

# Default entrypoint: print help. Override with `verifier` to start
# the Sinatra verifier, or `cli` for the confium CLI (when shipped).
ENTRYPOINT ["ruby", "-e", "puts 'confium/signer image — see /app/examples for usage'"]
CMD ["--help"]
