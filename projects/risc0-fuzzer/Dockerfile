FROM debian:bookworm as risc0

# run docker image in non interactive mode
ENV DEBIAN_FRONTEND noninteractive

# start from root directory
WORKDIR /root/

# install dependencies
RUN  apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential ca-certificates clang cmake curl dialog gcc git \
    jq libgmp-dev libgrpc++-dev libomp-dev libsecp256k1-dev \
    libssl-dev libsodium-dev libpqxx-dev nasm nlohmann-json3-dev  \
    pkg-config protobuf-compiler python3 python3-pip python3-venv \
    qemu-system ssh uuid-dev vim xz-utils && \
    rm -rf /var/lib/apt/lists/*

# install rust
ARG RUST_VERSION="stable"
RUN curl --proto '=https' --retry 10 --retry-connrefused --tlsv1.2 -fsSL https://sh.rustup.rs | \
    bash -s -- -y --profile minimal --default-toolchain=${RUST_VERSION}
ENV PATH="/root/.cargo/bin:${PATH}"

# install risc0 toolchain
RUN curl -L https://risczero.com/install | bash
ENV PATH="/root/.risc0/bin:${PATH}"
RUN rzup install cpp
RUN rzup install rust
# NOTE: We do not install the cargo client or the r0vm server!
#       This is either skipped completely or should be done once by the fuzzer client.

# copy selective libraries and projects
COPY ./libs /root/zkvm-fuzzing/libs
COPY ./projects/risc0-fuzzer /root/zkvm-fuzzing/projects/risc0-fuzzer

# install project dependencies (system wide)
RUN cd zkvm-fuzzing/projects/risc0-fuzzer/ && \
    python3 -m pip install -r requirements.txt --break-system-packages && \
    python3 -m pip install . --break-system-packages

# create and change directory to workspace
RUN mkdir -p /root/workspace
WORKDIR /root/workspace