# syntax=docker/dockerfile:1
ARG PORTMASTER_IMAGE=ghcr.io/monkeyx-net/portmaster-build-templates/portmaster-builder:aarch64-latest

FROM ${PORTMASTER_IMAGE} AS portmaster-base
USER root
WORKDIR /workspace

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ccache \
        libmpg123-dev \
        libx11-dev \
        libwayland-dev \
        libxkbcommon-dev \
        libxtst-dev \
        libdrm-dev \
        libgbm-dev \
        libpulse-dev \
        libasound2-dev \
        wayland-protocols

FROM portmaster-base AS game-build
ARG GAME=gtasa
ARG LAUNCHER_SCRIPT="Grand Theft Auto San Andreas.sh"
ARG BINARY_NAME=gtasa_linux
ARG GAME_TITLE="Grand Theft Auto: San Andreas"
ARG CONFIG_NAME=gtasa_nx.cfg
ARG APPSTATE_NAME=appstate.txt
ARG GTASA_DEBUG_LOG=OFF
ARG GTASA_FREE_AIM=OFF

ARG SDL_COMMIT=6057d79baf8321bf190479a699655f06cc2a962f
ARG SPIRV_CROSS_COMMIT=be71ee8c12cd7dc5ca8fa9581f708c2e8561fe2a

COPY . /workspace
# /root/.cache/ccache persists across builds so SDL/game recompiles hit cache.
RUN --mount=type=cache,target=/root/.cache/ccache,sharing=locked \
    chmod +x /workspace/scripts/portmaster-build.sh && \
    SDL_COMMIT="$SDL_COMMIT" \
    SPIRV_CROSS_COMMIT="$SPIRV_CROSS_COMMIT" \
    GAME="$GAME" \
    LAUNCHER_SCRIPT="$LAUNCHER_SCRIPT" \
    BINARY_NAME="$BINARY_NAME" \
    GAME_TITLE="$GAME_TITLE" \
    CONFIG_NAME="$CONFIG_NAME" \
    APPSTATE_NAME="$APPSTATE_NAME" \
    GTASA_DEBUG_LOG="$GTASA_DEBUG_LOG" \
    GTASA_FREE_AIM="$GTASA_FREE_AIM" \

    /workspace/scripts/portmaster-build.sh build

FROM scratch AS validation-artifact
ARG GAME=gtasa
COPY --from=game-build /workspace/build-${GAME}-portmaster/bionic_tls_test /bionic_tls_test
COPY --from=game-build /workspace/build-${GAME}-portmaster/elf_pages_test /elf_pages_test

FROM scratch AS artifact
COPY --from=game-build /workspace/package/ /
