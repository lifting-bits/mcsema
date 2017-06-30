#!/bin/sh

# TODO(artem): Move these too bootstrap once aarch64 is more supported
#              there is no reason yet to make everyone install cross-copiler headers
#              and associated utilities
sudo apt-get install g++-aarch64-linux-gnu gcc-aarch64-linux-gnu
