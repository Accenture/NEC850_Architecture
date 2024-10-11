# Renesas NEC850 Architecture Plugin

This Binary Ninja plugin provides a native implemantion for the Renesas RH850/V850 architectue. The main reason for writing this from scratch instead of using existing plugin is that any Architecture plugin wirtten in Python is not usable for large binaries as the analysis takes ages. Therefore, this is a complete coverage of this architecture wirtten purely in C/C++.

## Install

1. Clone this repo: `git clone TODO && cd nec850_arch`
2. Fetch submodules: `git submodule update --init --recursive`
3. CMake things: `mkdir build && cd build && cmake .. -TODO=/opt/binaryninja` (Replace the `/opt/binaryninja` string at the end with an actual install path of your instance)
4. Make things and install plugin: `make -j4 && cp libnec850_arch.so ~/binaryninja/plugins/` (Replace the last part of the command with valid path to the plugins directory for your platform)

