#!/usr/bin/env bash

# Use this script to build a 32-bit python compatible with IDA Pro. This
# is useful if you are running an x64 linux and you want to avoid using
# the bundled python.
#
# Once installed, you can access both the interpreter and the pip installer
# by sourcing the 'environment_variables' script.
#
# Things to remember
# 1. Either run this script under sudo or make sure you have access
#    to the PYTHON_PREFIX folder.
# 2. Install IDA Pro WITHOUT the built-in Python environment!
# 3. The bootstrap.sh script will still attempt to use the system
#    Python. This is because it is loading the root environment; you
#    can fix this by either removing the -H switch or by adding the
#    'source' command inside the root's bashrc/zshenv

#
# configuration
#

# same versions used by HexRays with IDA 6.95
PYTHON_VERSION='2.7.9'
SIP_VERSION='4.16.7'

PYTHON_PREFIX="/opt/IDAPython-${PYTHON_VERSION}"

function main
{
    printf "Selected Python version: ${PYTHON_VERSION}\n\n"

    if [ -d "$PYTHON_PREFIX" ] ; then
        printf "Removing: ${PYTHON_PREFIX}\n"

        rm -r "$PYTHON_PREFIX" 2> /dev/null
        if [ $? -ne 0 ] ; then
            printf 'Failed to remove the output folder\n'
            return 1
        fi
    fi

    printf 'Looking for missing dependencies...\n'
    CheckDependencies || return 1

    printf 'Downloading the Python source tarball...\n'
    DownloadPython || return 1

    printf 'Extracting the Python source code...\n'
    ExtractPython || return 1

    printf 'Configuring...\n'
    ConfigurePython || return 1

    printf 'Building...\n'
    BuildPython || return 1

    printf "Installing SetupTools...\n"
    InstallSetupTools || return 1

    printf "Installing PIP...\n"
    InstallPIP || return 1

    printf "Installing SIP...\n"
    InstallSIP || return 1

    printf "Generating the launcher...\n"
    InstallLauncher || return 1

    printf "Use the following file to use the newly built Python: ${PYTHON_PREFIX}/environment_variables\n\n"

    printf "Example:\n"
    printf "\tsource ${PYTHON_PREFIX}/environment_variables\n"
    printf "\tpython\n\n"

    return 0
}

function CheckDependencies
{
    local required_executable_list=(
        'tar'
        'curl'
        'openssl'
        'sed'
        'gcc'
        'g++'
    )

    for required_executable in ${required_executable_list[@]} ; do
        which "$required_executable" > /dev/null 2>&1
        if [ $? -ne 0 ] ; then
            printf 'The $required_executable executable could not be found!\n'
            return 1
        fi
    done

    # todo: make sure the required packages are installed
    #
    # this may be tricky, especially on ubuntu when mixing lib32* and :i386
    # packages. you most likely want to add at least zlib and openssl
    printf 'Please make sure you have all the required -dev packages (use the ":i386" ones if you are on Ubuntu). You most likely want to have at least zlib and openssl\n'

    rm "$LOG_FILE_NAME" 2> /dev/null
    return 0
}

function DownloadPython
{
    if [ -f "$PYTHON_TARBALL_NAME" ] ; then
        return 0
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    curl "https://www.python.org/ftp/python/${PYTHON_VERSION}/${PYTHON_TARBALL_NAME}" --output ${PYTHON_TARBALL_NAME} >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLogFile "$LOG_FILE_NAME" 'Failed to download the python tarball'
        return 1
    fi

    return 0
}

function ExtractPython
{
    if [ -d "$PYTHON_FOLDER_NAME" ] ; then
        local previous_install_prefix=`cat "${PYTHON_FOLDER_NAME}/install_prefix" 2> /dev/null`
        local previous_version=`cat "${PYTHON_FOLDER_NAME}/version" 2> /dev/null`

        local dirty=0
        if [[ "$previous_install_prefix" != "$PYTHON_PREFIX" ]] ; then
            dirty=1
        fi

        if [[ "$previous_version" != "$PYTHON_VERSION" ]] ; then
            dirty=1
        fi

        if [ $dirty -eq 0 ] ; then
            return 0
        fi

        printf "Your settings have been changed. Forcing a full rebuild...\n"

        rm -r "$PYTHON_FOLDER_NAME" 2> /dev/null
        if [ $? -ne 0 ] ; then
            printf "Failed to delete the python source folder\n"
            return 1
        fi
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    tar xf "$PYTHON_TARBALL_NAME" >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLogFile "$LOG_FILE_NAME" 'Failed to extract the python tarball'
        return 1
    fi

    printf "$PYTHON_PREFIX" > "${PYTHON_FOLDER_NAME}/install_prefix"
    printf "$PYTHON_VERSION" > "${PYTHON_FOLDER_NAME}/version"

    return 0
}

function ConfigurePython
{
    if [ -f "${PYTHON_FOLDER_NAME}/Modules/Setup" ] ; then
        return 0
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    ( cd "$PYTHON_FOLDER_NAME" && ./configure --enable-unicode=ucs4 --with-threads --enable-shared "--prefix=${PYTHON_PREFIX}" ) >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLogFile "$LOG_FILE_NAME" 'The configuration step has failed'
        return 1
    fi

    return 0
}

function BuildPython
{
    rm "$LOG_FILE_NAME" 2> /dev/null
    ( cd "$PYTHON_FOLDER_NAME" && make install -j `nproc` ) >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLogFile "$LOG_FILE_NAME" 'The build step has failed'
        return 1
    fi

    return 0
}

function InstallSetupTools
{
    local setuptools_temp_dir='SetupToolsData'

    mkdir "$setuptools_temp_dir"
    if [ $? -ne 0 ] ; then
        printf 'Failed to create the SetupTools temporary folder\n'
        return 1
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    curl 'https://bootstrap.pypa.io/ez_setup.py' --output "${setuptools_temp_dir}/ez_setup.py" >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        rm -r "$setuptools_temp_dir" 2> /dev/null

        ShowLogFile "$LOG_FILE_NAME" 'Failed to download the SetupTools installer'
        return 1
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    ( cd "$setuptools_temp_dir" && "${PYTHON_PREFIX}/bin/python" 'ez_setup.py')  >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        rm -r "$setuptools_temp_dir" 2> /dev/null

        ShowLogFile "$LOG_FILE_NAME" 'Failed to install the SetupTools'
        return 1
    fi

    rm -r "$setuptools_temp_dir" 2> /dev/null
    if [ $? -ne 0 ] ; then
        printf 'Failed to delete the SetupTools temporary folder\n'
        return 1
    fi

    python -c 'import pkg_resources' 2> /dev/null 2>&1
    if [ $? -ne 0 ] ; then
        printf 'Failed to install SetupTools\n'
        return 1
    fi

    return 0
}

function InstallPIP
{
    local pipinstaller_temp_dir='PIPInstallerData'

    mkdir "$pipinstaller_temp_dir"
    if [ $? -ne 0 ] ; then
        printf 'Failed to create the PIP temporary folder\n'
        return 1
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    curl 'https://bootstrap.pypa.io/get-pip.py' --output "${pipinstaller_temp_dir}/get-pip.py" >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        rm -r "$pipinstaller_temp_dir" 2> /dev/null

        ShowLogFile "$LOG_FILE_NAME" 'Failed to download the PIP installer'
        return 1
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    ( cd "$pipinstaller_temp_dir" && "${PYTHON_PREFIX}/bin/python" 'get-pip.py')  >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        rm -r "$pipinstaller_temp_dir" 2> /dev/null

        ShowLogFile "$LOG_FILE_NAME" 'Failed to install the PIP'
        return 1
    fi

    rm -r "$pipinstaller_temp_dir" 2> /dev/null
    if [ $? -ne 0 ] ; then
        printf 'Failed to delete the PIP temporary folder\n'
        return 1
    fi

    python -c 'import pip' 2> /dev/null 2>&1
    if [ $? -ne 0 ] ; then
        printf 'Failed to install PIP\n'
        return 1
    fi

    return 0
}

function InstallSIP
{
    local sip_tarball_name="sip-${SIP_VERSION}"
    local sip_download_link="https://sourceforge.net/projects/pyqt/files/sip/sip-${SIP_VERSION}/${sip_tarball_name}.tar.gz"

    local sipinstaller_temp_dir='SIPInstallerData'
    mkdir "$sipinstaller_temp_dir"

    if [ $? -ne 0 ] ; then
        printf 'Failed to create the SIP temporary folder\n'
        return 1
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    curl -L "$sip_download_link" --output "${sipinstaller_temp_dir}/${sip_tarball_name}.tar.gz" >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        rm -r "$sipinstaller_temp_dir" 2> /dev/null

        ShowLogFile "$LOG_FILE_NAME" 'Failed to download the SIP source tarball'
        return 1
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    ( cd "$sipinstaller_temp_dir" && tar xzf "${sip_tarball_name}.tar.gz" ) >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        rm -r "$sipinstaller_temp_dir" 2> /dev/null

        ShowLogFile "$LOG_FILE_NAME" 'Failed to extract the SIP source tarball'
        return 1
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    ( cd "${sipinstaller_temp_dir}/${sip_tarball_name}" && python "./configure.py" ) >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        rm -r "$sipinstaller_temp_dir" 2> /dev/null

        ShowLogFile "$LOG_FILE_NAME" 'Failed to configure the SIP source'
        return 1
    fi

    sed -i 's/CFLAGS = /CFLAGS = -m32 /g' "${sipinstaller_temp_dir}/${sip_tarball_name}/sipgen/Makefile"
    sed -i 's/CXXFLAGS = /CXXFLAGS = -m32 /g' "${sipinstaller_temp_dir}/${sip_tarball_name}/sipgen/Makefile"
    sed -i 's/LINK = g++/LINK = g++ -m32/g' "${sipinstaller_temp_dir}/${sip_tarball_name}/sipgen/Makefile"

    sed -i 's/CFLAGS = /CFLAGS = -m32 /g' "${sipinstaller_temp_dir}/${sip_tarball_name}/siplib/Makefile"
    sed -i 's/CXXFLAGS = /CXXFLAGS = -m32 /g' "${sipinstaller_temp_dir}/${sip_tarball_name}/siplib/Makefile"
    sed -i 's/LFLAGS = /LFLAGS = -m32 /g' "${sipinstaller_temp_dir}/${sip_tarball_name}/siplib/Makefile"

    rm "$LOG_FILE_NAME" 2> /dev/null
    ( cd "${sipinstaller_temp_dir}/${sip_tarball_name}" && make -j `nproc` ) >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        rm -r "$sipinstaller_temp_dir" 2> /dev/null

        ShowLogFile "$LOG_FILE_NAME" 'Failed to build the SIP source'
        return 1
    fi

    rm "$LOG_FILE_NAME" 2> /dev/null
    ( cd "${sipinstaller_temp_dir}/${sip_tarball_name}" && make install ) >> "$LOG_FILE_NAME" 2>&1
    if [ $? -ne 0 ] ; then
        rm -r "$sipinstaller_temp_dir" 2> /dev/null

        ShowLogFile "$LOG_FILE_NAME" 'Failed to install the SIP library'
        return 1
    fi

    rm -r "$sipinstaller_temp_dir" 2> /dev/null
    if [ $? -ne 0 ] ; then
        printf 'Failed to delete the SIP temporary folder\n'
        return 1
    fi

    python -c 'import sip' 2> /dev/null 2>&1
    if [ $? -ne 0 ] ; then
        printf 'Failed to install SIP\n'
        return 1
    fi

    return 0
}

function InstallLauncher
{
    printf "export PYTHONPATH='${PYTHONPATH}'\n" > "${PYTHON_PREFIX}/environment_variables"
    if [ $? -ne 0 ] ; then
        printf "Failed to create the launcher file\n"
        return 1
    fi

    printf "export PATH=\"${PYTHON_PREFIX}/bin:\${PATH}\"\n" >> "${PYTHON_PREFIX}/environment_variables"
    if [ $? -ne 0 ] ; then
        printf "Failed to create the launcher file\n"
        return 1
    fi

    printf "export LIBRARY_PATH='${PYTHON_PREFIX}/lib'\n" >> "${PYTHON_PREFIX}/environment_variables"
    if [ $? -ne 0 ] ; then
        printf "Failed to create the launcher file\n"
        return 1
    fi

    printf "export LD_LIBRARY_PATH='${PYTHON_PREFIX}/lib'\n" >> "${PYTHON_PREFIX}/environment_variables"
    if [ $? -ne 0 ] ; then
        printf "Failed to create the launcher file\n"
        return 1
    fi

    return 0
}

function ShowLogFile
{
    if [ $# -ne 2 ] ; then
        printf 'Usage:\n'
        printf '\tShowLogFile /path/to/log/file "message"\n'
        return 1
    fi

    local log_file_path="$1"
    local message="$2"

    if [ ! -f "$log_file_path" ] ; then
        printf "ShowLogFile: the following file could not be found: ${log_file_path}\n"
        return 1
    fi

    printf '###\n'
    cat "$log_file_path"
    printf '###\n\n'

    printf "${message}\n"
    return 0
}

# python source folder and tarball name
PYTHON_FOLDER_NAME="Python-${PYTHON_VERSION}"
PYTHON_TARBALL_NAME="${PYTHON_FOLDER_NAME}.tar.xz"

# output log
LOG_FILE_NAME="PythonBuilder.log"

#
# exported variables; needed to correctly build
# sub-targets (i.e.: pip)
#

# default compile options
export CFLAGS='-m32'
export LDFLAGS='-m32'

# python environment
export PYTHONPATH="${PYTHON_PREFIX}/lib/python2.7/site-packages:${PYTHON_PREFIX}"
export PATH="${PYTHON_PREFIX}/bin:${PATH}"

export LIBRARY_PATH="${PYTHON_PREFIX}/lib"
export LD_LIBRARY_PATH="${PYTHON_PREFIX}/lib"

main $@
exit $?

