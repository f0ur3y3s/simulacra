# Ghidra headless decompiler for simulacra (pseudo-C for objects and PE targets).
#
# Modelled on tiresias's backend/Dockerfile.ghidra-mcp: the same pinned, checksum-verified
# Ghidra release on a JDK base (Java post-scripts are compiled at runtime, so a JRE is not
# enough), run as an unprivileged user. None of ghidra-mcp / BinExport: one-shot
# `analyzeHeadless` with our own post-script is all simulacra needs.
#
#   docker build -t simulacra-ghidra:12.1.2 docker/ghidra
#
# Run (what simulacra.decomp does): the binary on stdin, JSON on stdout, no network.
#   (stdin: a tar of binary/<name> + functions.txt; see decompile.sh and decomp/ghidra.py)

FROM eclipse-temurin:21-jdk AS fetch

# Keep in sync with GHIDRA_IMAGE in src/simulacra/decomp/ghidra.py.
ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_DATE=20260605
ARG GHIDRA_SHA256=b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d

RUN apt-get update && apt-get install -y --no-install-recommends wget unzip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt
RUN wget -q \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
      -O ghidra.zip \
    && echo "${GHIDRA_SHA256}  ghidra.zip" | sha256sum -c - \
    && unzip -q ghidra.zip \
    && rm ghidra.zip \
    && mv ghidra_* ghidra \
    # Docs, debugger and server pieces are unused headless; dropping them halves the image.
    && rm -rf ghidra/docs ghidra/Ghidra/Debug ghidra/server ghidra/Extensions/Eclipse

FROM eclipse-temurin:21-jdk

COPY --from=fetch /opt/ghidra /opt/ghidra
COPY scripts/ /opt/simulacra-scripts/
COPY decompile.sh /usr/local/bin/decompile
RUN sed -i 's/\r$//' /usr/local/bin/decompile && chmod 0755 /usr/local/bin/decompile

ENV GHIDRA_HOME=/opt/ghidra \
    MAXMEM=3G

# Ghidra parses untrusted binaries: run unprivileged (uid 10001 as in tiresias, since the
# base image already has a uid-1000 `ubuntu` user).
RUN groupadd --gid 10001 ghidra \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/ghidra ghidra
ENV HOME=/home/ghidra
USER ghidra
WORKDIR /home/ghidra

# Smoke test: analyzeHeadless starts and finds the script directory.
RUN /opt/ghidra/support/analyzeHeadless /tmp smoke -scriptPath /opt/simulacra-scripts \
      -deleteProject 2>&1 | tail -3 ; rm -rf /tmp/smoke* /home/ghidra/.ghidra /home/ghidra/.config

ENTRYPOINT ["/usr/local/bin/decompile"]
