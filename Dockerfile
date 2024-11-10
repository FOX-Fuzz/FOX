#
# This Dockerfile for AFLplusplus uses Ubuntu 22.04 jammy and
# installs LLVM 14 for afl-clang-lto support :-)
#

FROM ubuntu:focal
# If we want to use jammy and correspondingly gcc-12, llvm-14, we need to
# update docker version to 20.x
# FROM ubuntu:jammy

ARG DEBIAN_FRONTEND=noninteractive

ENV NO_ARCH_OPT=1

RUN apt-get update && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    # AFL++ dependencies
    automake \
    cmake \
    meson \
    ninja-build \
    bison flex \
    build-essential \
    git \
    python3 python3-dev python3-setuptools python-is-python3 \
    libtool libtool-bin \
    libglib2.0-dev \
    libcairo2-dev \
    wget vim jupp nano bash-completion less \
    apt-utils apt-transport-https ca-certificates gnupg dialog \
    libpixman-1-dev \
    gnuplot-nox \
    # Unzip seeds
    unzip \
    # QoL + Eval pipeline dependencies
    sudo screen beanstalkd python3-pip python3.8-venv \
    && rm -rf /var/lib/apt/lists/*


RUN apt-get update && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    lsb-release wget software-properties-common gnupg

RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x llvm.sh
RUN sudo ./llvm.sh 15

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 10 \
                        --slave /usr/bin/clang++ clang++ /usr/bin/clang++-15 \
                        --slave /usr/bin/opt opt /usr/bin/opt-15
RUN update-alternatives --install /usr/lib/llvm llvm /usr/lib/llvm-15 20 \
                        --slave /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-15 \
                        --slave /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-15


# Setup a new user

# Make the user reflect the host user
ARG USER_NAME=docker
ARG UID=1000
ARG GID=1000

RUN groupadd -g $GID -o $USER_NAME
RUN useradd -m -u $UID -g $GID -G sudo -o -s /bin/bash -d /home/$USER_NAME $USER_NAME
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Move into userland
USER $USER_NAME

# Prepare the user's workspace
RUN sudo mkdir -p /workspace && \
    sudo chown $USER_NAME:$USER_NAME /workspace
WORKDIR /workspace

# Add ~/.local/bin and /usr/local/go/bin to the PATH
RUN mkdir -p /home/$USER_NAME/.local/bin
ENV PATH="/home/$USER_NAME/.local/bin:/usr/local/go/bin:/workspace/gllvm_bins:${PATH}"
RUN echo "export PATH=$PATH" >> ~/.bashrc
# 
# # AFL++ env variables
ENV NO_ARCH_OPT=1
ENV IS_DOCKER=1

ENV NO_CORESIGHT=1
ENV NO_NYX=1

ENV LLVM_CONFIG=llvm-config-15
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_TRY_AFFINITY=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

# Import and setup OptFuzz
RUN git clone https://github.com/FOX-Fuzz/FOX.git OptFuzzer

WORKDIR /workspace/OptFuzzer
RUN export CC=clang-15 && export CXX=clang++-15 && make clean && \
    make 

RUN sudo ln -s /usr/bin/llvm-nm-15 /usr/local/bin/llvm-nm

# Add evaluation pipeline
WORKDIR /workspace
RUN mkdir -p /workspace/fuzzopt-eval
WORKDIR /workspace/fuzzopt-eval
COPY --chown=$UID:$GID  . /workspace/fuzzopt-eval/fuzzdeployment

# Clean up unnecessary directories
RUN rm -r /workspace/fuzzopt-eval/fuzzdeployment/docker
RUN rm -r /workspace/fuzzopt-eval/fuzzdeployment/magma_artifact

# Fix python dependencies
WORKDIR /workspace/fuzzopt-eval/fuzzdeployment/scripts
RUN pip install "cython<3.0.0" wheel
RUN pip install "pyyaml==5.4.1" --no-build-isolation
RUN pip install pyelftools
RUN pip install -r requirements.txt

WORKDIR /workspace/fuzzopt-eval/fuzzdeployment
