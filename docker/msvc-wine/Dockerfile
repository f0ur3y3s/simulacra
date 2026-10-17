# MSVC under Wine for mscmatch. One image per toolchain; see src/mscmatch/toolchain/registry.toml.
#
# Build args select the pinned toolset; the final RUN asserts that cl.exe reports the expected
# build so a silently-updated manifest cannot produce an image with the wrong compiler.
#
#   docker build -t msvc-<cl build>-sdk-<sdk> \
#     --build-arg VS_MAJOR=17 --build-arg MSVC_VERSION=17.14 \
#     --build-arg SDK_VERSION=10.0.26100 --build-arg EXPECT_CL=19.44.35229 docker/msvc-wine
#
# Building downloads MSVC + Windows SDK from Microsoft and accepts the Visual Studio license.

FROM debian:trixie-slim

ARG MSVC_WINE_COMMIT=514f8ea34842cd6d831804d0e9658d3a32870ae1
ARG VS_MAJOR=17
ARG MSVC_VERSION=17.14
ARG SDK_VERSION=10.0.26100

ENV DEBIAN_FRONTEND=noninteractive \
    WINEDEBUG=-all \
    WINEARCH=win64 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wine wine64 python3 msitools ca-certificates git procps && \
    apt-get clean -y && rm -rf /var/lib/apt/lists/*

RUN $(command -v wine64 || command -v wine) wineboot --init && while pgrep wineserver > /dev/null; do sleep 1; done

WORKDIR /opt/msvc-wine-src
RUN git clone https://github.com/mstorsjo/msvc-wine.git . && git checkout ${MSVC_WINE_COMMIT}

RUN ./vsdownload.py --accept-license --major ${VS_MAJOR} \
        --msvc-version ${MSVC_VERSION} --sdk-version ${SDK_VERSION} \
        --architecture x64 --host-arch x64 \
        --with-asan no --with-atl no \
        --dest /opt/msvc && \
    ./install.sh /opt/msvc && \
    cd / && rm -rf /opt/msvc-wine-src

COPY mscmatch-runner.py /usr/local/bin/mscmatch-runner
RUN chmod +x /usr/local/bin/mscmatch-runner

# Smoke test + version assertion. cl prints its banner to stderr, interleaved with usage text.
# Declared here (not at the top) so changing it does not invalidate the download layer.
ARG EXPECT_CL=19.44.35229
RUN mkdir -p /work && cd /work && printf 'int f(int x){return x*3;}\n' > t.c && \
    /opt/msvc/bin/x64/cl /nologo /c /Brepro t.c && \
    /opt/msvc/bin/x64/cl 2>&1 | grep -m1 "Compiler Version" | tee /opt/msvc/CL_BANNER && \
    if [ -n "${EXPECT_CL}" ]; then grep -q "Version ${EXPECT_CL} " /opt/msvc/CL_BANNER; fi && \
    rm -rf /work/* && while pgrep wineserver > /dev/null; do sleep 1; done

WORKDIR /work
# Long-lived worker: a persistent wineserver keeps per-compile startup cost low.
CMD ["sh", "-c", "wineserver -p -f"]
