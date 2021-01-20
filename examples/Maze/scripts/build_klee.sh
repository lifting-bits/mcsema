#!/bin/bash
#
# Build and install KLEE.
#
set -euo pipefail

LLVM_VER=10
CXX_COMMON_VER=0.1.1
KLEE_UCLIBC_VER=1.2
KLEE_VER=2.2

OCWD="$(pwd -P)"
SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
BUILD_DIR="$(dirname "$SCRIPT_DIR")/build"
INSTALL_DIR="$(dirname "$SCRIPT_DIR")/installed"

export MAKEFLAGS="-j$(nproc)"

msg() {
    echo -e "[+] ${1-}" >&2
}

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

get_distro() {
    if test -f /etc/os-release; then # freedesktop.org and systemd
        . /etc/os-release
        echo $NAME | cut -f 1 -d ' ' | tr '[:upper:]' '[:lower:]'
    elif type lsb_release >/dev/null 2>&1; then # linuxbase.org
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    elif test -f /etc/lsb-release; then
        . /etc/lsb-release
        echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]'
    elif test -f /etc/arch-release; then
        echo "arch"
    elif test -f /etc/debian_version; then
        # Older Debian, Ubuntu
        echo "debian"
    elif test -f /etc/SuSe-release; then
        # Older SuSE
        echo "opensuse"
    elif test -f /etc/fedora-release; then
        # Older Fedora
        echo "fedora"
    elif test -f /etc/redhat-release; then
        # Older Red Hat, CentOS
        echo "centos"
    elif type uname >/dev/null 2>&1; then
        # Fall back to uname
        echo "$(uname -s)"
    else
        die "Unable to determine the distribution"
    fi
}

usage() {
    cat <<EOF
[!] Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v] [--llvm LLVM_version]

    Build and install KLEE.

    Available options:

    -h, --help      Print this help and exit
    -v, --verbose   Print script debug info
    --llvm          Specify LLVM version (9 or 10, default: 10)
EOF
}

parse_params() {
    while :; do
        case "${1-}" in
        -h | --help) usage; exit ;;
        -v | --verbose) set -x ;;
        --llvm)
            LLVM_VER="${2-}"
            if [ "$LLVM_VER" != "9" -a "$LLVM_VER" != "10" ]; then
                die "Invalid LLVM version: $LLVM_VER\n$(usage)"
            fi
            shift
            ;;
        --libcxx) LIBCXX=1 ;; # enable KLEE_LIBCXX
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done
}

install_cxx_common() {
    pushd "$BUILD_DIR" >/dev/null
    URL="https://github.com/trailofbits/cxx-common/releases/download/v${CXX_COMMON_VER}/vcpkg_ubuntu-20.04_llvm-${LLVM_VER}_amd64.tar.xz"
    FILE="$(basename "$URL")"
    if [ ! -f "$FILE" ]; then
        msg "Downloading cxx-common..."
        curl -LO "$URL"
    fi
    msg "Extracting cxx-common..."
    tar xf $FILE
    mv vcpkg_ubuntu-20.04_llvm-${LLVM_VER}_amd64 "$INSTALL_DIR/cxx-common"
    popd >/dev/null
}

install_klee_uclibc() {
    vcpkg_prefix="$INSTALL_DIR/cxx-common/installed/x64-linux-rel"
    export PATH="$vcpkg_prefix/bin:${PATH}"
    export CC="$vcpkg_prefix/bin/clang"
    export CXX="$vcpkg_prefix/bin/clang++"

    pushd "$BUILD_DIR" >/dev/null
    URL="https://github.com/klee/klee-uclibc/archive/klee_uclibc_v${KLEE_UCLIBC_VER}.tar.gz"
    FILE="$(basename "$URL")"
    if [ ! -f "$FILE" ]; then
        msg "Downloading klee-uclibc..."
        curl -LO "$URL"
    fi
    msg "Extracting klee-uclibc..."
    tar xf $FILE

    srcdir="$BUILD_DIR/klee-uclibc-klee_uclibc_v${KLEE_UCLIBC_VER}"
    pkgdir="$INSTALL_DIR/klee-uclibc"
    pushd "$srcdir" >/dev/null
    msg "Building klee-uclibc..."
    "$srcdir"/configure --make-llvm-lib --with-cc="$CC"
    sed -i "$srcdir"/.config \
        -e "s|DEVEL_PREFIX=\"[^\"]*\"|DEVEL_PREFIX=\"$pkgdir/usr\"|" \
        -e "s|RUNTIME_PREFIX=\"[^\"]*\"|RUNTIME_PREFIX=\"$pkgdir/usr\"|"
    make
    msg "Installing klee-uclibc..."
    make install
    popd >/dev/null
    popd >/dev/null
}

install_klee() {
    vcpkg_prefix="$INSTALL_DIR/cxx-common/installed/x64-linux-rel"
    export PATH="$vcpkg_prefix/bin:${PATH}"
    export CC="$vcpkg_prefix/bin/clang"
    export CXX="$vcpkg_prefix/bin/clang++"

    pushd "$BUILD_DIR" >/dev/null
    URL="https://github.com/klee/klee/archive/v${KLEE_VER}.tar.gz"
    FILE="$(basename "$URL")"
    if [ ! -f "$FILE" ]; then
        msg "Downloading klee..."
        curl -LO "$URL"
    fi
    msg "Extracting klee..."
    tar xf $FILE
    URL="https://github.com/google/googletest/archive/release-1.10.0.tar.gz"
    FILE="$(basename "$URL")"
    if [ ! -f "$FILE" ]; then
        msg "Downloading googletest..."
        curl -LO "$URL"
    fi
    msg "Extracting googletest..."
    tar xf $FILE
    msg "Copying KLEE patches..."
    cp "$SCRIPT_DIR/00-ret-void.patch" "$BUILD_DIR"
    cp "$SCRIPT_DIR/01-skip-Z3_get_error_msg-check.patch" "$BUILD_DIR"

    srcdir="$BUILD_DIR/klee-${KLEE_VER}"
    gtestdir="$BUILD_DIR/googletest-release-1.10.0/googletest"
    pkgdir="$INSTALL_DIR/klee"
    pushd "$srcdir" >/dev/null
    msg "Patching klee..."
    patch -Np1 -i "$BUILD_DIR/00-ret-void.patch"
    patch -Np1 -i "$BUILD_DIR/01-skip-Z3_get_error_msg-check.patch"
    mkdir -p "$srcdir/build"
    pushd "$srcdir/build" >/dev/null
    msg "Building klee..."
    cmake \
        -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_CXX_COMPILER="$CXX" \
        -DENABLE_TCMALLOC=ON \
        -DENABLE_POSIX_RUNTIME=ON \
        -DENABLE_KLEE_UCLIBC=ON \
        -DKLEE_UCLIBC_PATH="$INSTALL_DIR/klee-uclibc/usr" \
        -DENABLE_SOLVER_Z3=ON \
        -DENABLE_SOLVER_STP=OFF \
        -DENABLE_SOLVER_METASMT=OFF \
        -DZ3_INCLUDE_DIRS="$vcpkg_prefix/include" \
        -DZ3_LIBRARIES="$vcpkg_prefix/lib/libz3.a" \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR/klee/usr" \
        -DCMAKE_INSTALL_LIBDIR="$INSTALL_DIR/klee/usr/lib" \
        -DCMAKE_BUILD_TYPE=Release \
        -DGTEST_SRC_DIR="$gtestdir" \
        -DENABLE_UNIT_TESTS=ON \
        -DENABLE_SYSTEM_TESTS=ON \
        -DCMAKE_VERBOSE_MAKEFILE=True \
        "$srcdir"
    make
    msg "Testing klee..."
    make systemtests
    msg "Installing klee..."
    make install
    popd >/dev/null
    popd >/dev/null
    popd >/dev/null
}

main() {
    parse_params $@

    if [ -e "$INSTALL_DIR" ]; then
        while true; do
            echo -n "'$INSTALL_DIR' exists. Remove it? [Y/n] "
            read remove
            remove="$(echo "$remove" | tr '[:upper:]' '[:lower:]')"
            [ -z "${remove##y*}" ] && \
                { rm -rf "$INSTALL_DIR"; break; }
            [ -z "${remove##n*}" ] && \
                die "'$INSTALL_DIR' exists"
        done
    fi
    mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

    DISTRO="$(get_distro)"
    msg "LLVM version: $LLVM_VER"
    msg "cxx-common version: $CXX_COMMON_VER"
    msg "KLEE-uclibc version: $KLEE_UCLIBC_VER"
    msg "KLEE version: $KLEE_VER"
    msg "Build location: $BUILD_DIR"
    msg "Install location: $INSTALL_DIR"
    msg "Detected distribution: $DISTRO"

    if [ "$DISTRO" = "arch" ]; then
        makedepends=(base-devel curl git cmake wget)
        depends=(libcap sqlite gperftools zlib python python-tabulate
                 lib32-glibc lib32-gcc-libs)
        msg "Installing dependencies..."
        sudo pacman -Syq --needed --noconfirm --asdeps ${makedepends[@]} ${depends[@]}

    elif [ "$DISTRO" = "ubuntu" ]; then
        depends=(build-essential liblzma-dev libssl-dev curl libtinfo-dev
                 ccache libncurses5-dev libncursesw5-dev libarchive-tools)
        depends+=(python3 wget) # klee-uclibc
        depends+=(libcap-dev libsqlite3-dev libgoogle-perftools-dev zlib1g-dev
                  python3 python3-pip python3-tabulate gcc-multilib g++-multilib
                  git cmake) # klee-git
        msg "Installing dependencies..."
        sudo apt update -y -qq
        sudo apt install -y -qq ${depends[@]}
        pip3 install "lit==0.${LLVM_VER}.0"
        if ! command -v python >/dev/null 2>&1; then
            sudo ln -s "$(which python3)" /usr/bin/python
        fi

    else
        die "Unsupported distribution: $DISTRO"
    fi

    install_cxx_common
    install_klee_uclibc
    install_klee

    msg "DONE"
}


main $@

# vim: set ts=4 sw=4 et:
