# Linux verification image for Sigil's cross-component suites.
#
# The repo is gated exclusively on macOS and every CI job runs on ubuntu-latest.
# Nothing checked that the two agreed, and it cost three workflows that were red
# for several phases while the local gate printed ALL GREEN.
#
# arm64-native (this dev machine) rather than emulated amd64: the point is to
# exercise GNU coreutils and Linux path/toolchain assumptions, not the ISA.
FROM rust:1-bookworm

ARG GO_VERSION=1.25.12

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git python3 jq procps \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" \
      | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN go version && cargo --version && node --version && python3 --version
WORKDIR /work
