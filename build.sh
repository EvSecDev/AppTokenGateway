#!/bin/bash
function usage {
	echo "Usage $0
Program Build Script and Helpers

Options:
  -b           Build the program using defaults
  -a <arch>    Architecture of compiled binary (amd64, arm64) [default: amd64]
  -o <os>      Which operating system to build for (linux, windows) [default: linux]
  -h           Print this help menu
"
}

# Variables
GOARCH="amd64"
GOOS="linux"
readonly outputBinaryName="atg"

while getopts 'a:o:bh' opt; do
	case "$opt" in
		'a')
			GOARCH="$OPTARG"
			;;
		'b')
			export CGO_ENABLED=0
			export GOARCH
			export GOOS
			echo "[*] Compiling program binary..."
			go build -o "$outputBinaryName" -trimpath -a -ldflags '-s -w -buildid= -extldflags "-static"' cmd/atg/main.go
			if [[ $? != 0 ]]; then
				echo -e "[-] Build Failed"
			else
				echo -e "[+] Build complete. Executable located at $(pwd)/$outputBinaryName"
			fi
			;;
		'o')
			GOOS="$OPTARG"
			;;
		'h')
			usage
			exit 0
			;;
		*)
			echo -e "ERROR: Unknown option or combination of options." >&2
			usage
			exit 1
			;;
	esac
done
