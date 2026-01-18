FROM debian:bookworm as jolt

# run docker image in non interactive mode
ENV DEBIAN_FRONTEND noninteractive

# start from root directory
WORKDIR /root/

# install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential ca-certificates clang cmake curl dialog gcc git \
    jq libgmp-dev libgrpc++-dev libomp-dev libsecp256k1-dev \
    libssl-dev libsodium-dev libpqxx-dev nasm nlohmann-json3-dev  \
    pkg-config protobuf-compiler python3 python3-pip qemu-system \
    ssh uuid-dev vim xz-utils && \
    rm -rf /var/lib/apt/lists/*

# install rust
ARG RUST_VERSION="nightly-2025-04-06"
RUN curl --proto '=https' --retry 10 --retry-connrefused --tlsv1.2 -fsSL https://sh.rustup.rs | \
    bash -s -- -y --profile minimal --default-toolchain=${RUST_VERSION}
ENV PATH="/root/.cargo/bin:${PATH}"

# copy selective libraries and projects
COPY ./libs /root/zkvm-fuzzing/libs
COPY ./projects/jolt-fuzzer /root/zkvm-fuzzing/projects/jolt-fuzzer

# install project dependencies (system wide)
RUN cd zkvm-fuzzing/projects/jolt-fuzzer/ && \
    python3 -m pip install -r requirements.txt --break-system-packages && \
    python3 -m pip install . --break-system-packages

# create and change directory to workspace
RUN mkdir -p /root/workspace
WORKDIR /root/workspace
