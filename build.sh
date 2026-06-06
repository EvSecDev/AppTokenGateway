#!/bin/bash
# Variables
repoRoot=$(pwd)
export CGO_ENABLED=0
GOARCH="amd64"
GOOS="linux"
buildFull='false'

if [[ -z $repoRoot ]]; then
	echo -e "[-] ERROR: Failed to determine current directory" >&2
	exit 1
fi

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

while getopts 'a:o:bh' opt; do
	case "$opt" in
		'a')
			GOARCH="$OPTARG"
			;;
		'b')
			buildmode='true'
			;;
		'o')
			GOOS="$OPTARG"
			;;
		'h')
			usage
			exit 0
			;;
		*)
			usage
			exit 0
			;;
	esac
done

if [[ $buildmode == true ]]; then
	export GOARCH
	export GOOS
	echo "[*] Compiling program binary..."
	go build -o "$repoRoot"/atg -trimpath -a -ldflags '-s -w -buildid= -extldflags "-static"' ./*.go
	if [[ $? != 0 ]]; then
		echo -e "[-] Build Failed"
	else
		echo -e "[+] Build complete"
	fi
else
	echo -e "ERROR: Unknown option or combination of options." >&2
	usage
	exit 1
fi
