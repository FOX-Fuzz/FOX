#!/bin/bash

#install packages 

   sudo apt-get update && sudo apt-get -y install --no-install-suggests --no-install-recommends automake cmake meson ninja-build bison flex build-essential git python3 python3-dev python3-setuptools python-is-python3 libtool libtool-bin libglib2.0-dev libcairo2-dev wget vim jupp nano bash-completion less apt-utils apt-transport-https ca-certificates gnupg dialog libpixman-1-dev gnuplot-nox unzip screen beanstalkd python3-pip python3-venv && sudo rm -rf /var/lib/apt/lists/*

sudo apt-get update && sudo apt-get -y install --no-install-suggests --no-install-recommends lsb-release wget software-properties-common gnupg

wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 15

sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 10 --slave /usr/bin/clang++ clang++ /usr/bin/clang++-15 --slave /usr/bin/opt opt /usr/bin/opt-15

sudo update-alternatives --install /usr/lib/llvm llvm /usr/lib/llvm-15 20 --slave /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-15 --slave /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-15

# Import and setup OptFuzz

# Check if OptFuzzer directory exists
if [ ! -d "OptFuzzer" ]; then
    echo "OptFuzzer directory does not exist. Cloning repository..."
    git clone https://github.com/FOX-Fuzz/FOX.git OptFuzzer
else
    echo "OptFuzzer directory already exists. Skipping git clone."
fi

cd ./OptFuzzer
export CC=clang-15 && export CXX=clang++-15 && make clean && \
    make 

# Check if the symbolic link already exists
if [ ! -L /usr/local/bin/llvm-nm ]; then
    echo "Creating symbolic link for llvm-nm..."
    sudo ln -s /usr/bin/llvm-nm-15 /usr/local/bin/llvm-nm
else
    echo "Symbolic link for llvm-nm already exists. Skipping this step."
fi

