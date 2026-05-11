#!/bin/sh
set -e

usage() {
  this=$1
  cat <<EOF
$this: download binaries for sigstore-kms-ovhcloud

Usage: $this [-b <bindir>] [-d] [<tag>]
  -b sets bindir or installation directory, Defaults to $HOME/.local/bin
  -d turns on debug logging
   <tag> is a tag from
   https://github.com/ovh/sigstore-kms-ovhcloud/releases
   If tag is missing, then the latest will be used.

EOF
  exit 2
}

parse_args() {
  [ "$BINDIR" ] || for dir in "$XDG_BIN_HOME" "$HOME/.local/bin"; do
    if [ -d "$dir" ]; then
      BINDIR=$dir
      break
    fi
  done
  BINDIR=${BINDIR:-$HOME/.local/bin}
  while getopts "b:dh?x" arg; do
    case "$arg" in
      b) BINDIR="$OPTARG" ;;
      d) log_set_priority 10 ;;
      h | \?) usage "$0" ;;
      x) set -x ;;
    esac
  done
  shift $((OPTIND - 1))
  TAG=$1
}

execute() {
  tmpdir=$(mktemp -d)
  log_debug "downloading files into ${tmpdir}"
  http_download "${tmpdir}/${TARBALL}" "${TARBALL_URL}"
  (cd "${tmpdir}" && untar "${TARBALL}")
  [ -d "$BINDIR" ] || install -d "$BINDIR"
  BINARY_IN_ARCHIVE="${BINARY}-${OS}-${ARCH}-${VERSION}"
  if [ "$OS" = "windows" ]; then
    BINARY="${BINARY}.exe"
  fi
  install "$tmpdir/$BINARY_IN_ARCHIVE" "${BINDIR%/}/$BINARY"
  log_info "installed ${BINDIR%/}/$BINARY"

  rm -rf "${tmpdir}"
}

tag_to_version() {
  if [ -z "${TAG}" ]; then
    log_info "checking GitHub for latest tag"
  else
    log_info "checking GitHub for tag '${TAG}'"
  fi
  REALTAG=$(github_release "$OWNER/$REPO" "${TAG}") && true
  if test -z "$REALTAG"; then
    log_crit "unable to find '${TAG}' - use 'latest' or see https://github.com/${PREFIX}/releases for details"
    exit 1
  fi
  # if version starts with 'v', remove it
  TAG="$REALTAG"
  VERSION=${TAG#v}
}

adjust_format() {
  # change format (tar.gz or zip) based on OS
  case ${OS} in
    windows) FORMAT=zip ;;
  esac
  true
}

cat /dev/null <<EOF
------------------------------------------------------------------------
https://github.com/client9/shlib - portable posix shell functions
Public domain - http://unlicense.org
https://github.com/client9/shlib/blob/HEAD/LICENSE.md
but credit (and pull requests) appreciated.
------------------------------------------------------------------------
EOF
is_command() {
  command -v "$1" >/dev/null
}
echoerr() {
  echo "$@" 1>&2
}
_logp=6
log_set_priority() {
  _logp="$1"
}
log_priority() {
  if test -z "$1"; then
    echo "$_logp"
    return
  fi
  [ "$1" -le "$_logp" ]
}
log_tag() {
  case $1 in
    0) echo "emerg" ;;
    1) echo "alert" ;;
    2) echo "crit" ;;
    3) echo "err" ;;
    4) echo "warning" ;;
    5) echo "notice" ;;
    6) echo "info" ;;
    7) echo "debug" ;;
    *) echo "$1" ;;
  esac
}
log_debug() {
  log_priority 7 || return 0
  echoerr "$(log_prefix)" "$(log_tag 7)" "$@"
}
log_info() {
  log_priority 6 || return 0
  echoerr "$(log_prefix)" "$(log_tag 6)" "$@"
}
log_err() {
  log_priority 3 || return 0
  echoerr "$(log_prefix)" "$(log_tag 3)" "$@"
}
log_crit() {
  log_priority 2 || return 0
  echoerr "$(log_prefix)" "$(log_tag 2)" "$@"
}
uname_os() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    mysys* | mingw* | cygwin* | windows*) os="windows" ;;
  esac
  echo "$os"
}

uname_arch() {
  arch=$(uname -m)
  case "$arch" in
    x86_64) echo "amd64" ;;
    aarch64 | arm64) echo "arm64" ;;
    *)
      log_crit "unsupported architecture: $arch"
      exit 1
      ;;
  esac
}

uname_os_check() {
  os=$(uname_os)
  case "$os" in
    darwin) return 0 ;;
    linux) return 0 ;;
    windows) return 0 ;;
  esac
  log_crit "uname_os_check '$(uname -s)' got converted to '$os' which is not a GOOS value."
  return 1
}

untar() {
  tarball=$1
  case "${tarball}" in
    *.tar.gz | *.tgz) tar --no-same-owner -xzf "${tarball}" ;;
    *.tar) tar --no-same-owner -xf "${tarball}" ;;
    *.zip) unzip "${tarball}" ;;
    *)
      log_err "untar unknown archive format for ${tarball}"
      return 1
      ;;
  esac
}

http_download_curl() {
  local_file=$1
  source_url=$2
  header=$3

  if [ -z "$header" ]; then
    code=$(curl -w '%{http_code}' -sL -o "$local_file" "$source_url")
  else
    code=$(curl -w '%{http_code}' -sL -H "$header" -o "$local_file" "$source_url")
  fi
  if [ "$code" != "200" ]; then
    log_err "http_download_curl received HTTP status $code"
    return 1
  fi
  return 0
}

http_download_wget() {
  local_file=$1
  source_url=$2
  header=$3
  _wget_output=""
  _wget_exit=""
  if [ -z "$header" ]; then
    _wget_output=$(wget --server-response --quiet -O "$local_file" "$source_url" 2>&1)
  else
    _wget_output=$(wget --server-response --quiet --header "$header" -O "$local_file" "$source_url" 2>&1)
  fi
  _wget_exit=$?
  if [ "$_wget_exit" -ne 0 ]; then
    log_err "http_download_wget failed: wget exited with status $_wget_exit"
    return 1
  fi
  _wget_code=$(echo "$_wget_output" | awk '/^  HTTP/{print $2}' | tail -n1)
  if [ "$code" != "200" ]; then
    log_err "http_download_wget received HTTP status $_wget_code"
    return 1
  fi
  return 0
}

http_download() {
  log_debug "http_download $2"
  if is_command curl; then
    http_download_curl "$@"
    return
  elif is_command wget; then
    http_download_wget "$@"
    return
  fi
  log_crit "http_download unable to find wget or curl"
  return 1
}

http_copy() {
  tmp=$(mktemp)
  http_download "${tmp}" "$1" "$2" || return 1
  body=$(cat "$tmp")
  rm -f "${tmp}"
  echo "$body"
}

github_release() {
  owner_repo=$1
  version=$2
  test -z "$version" && version="latest"
  giturl="https://github.com/${owner_repo}/releases/${version}"
  json=$(http_copy "$giturl" "Accept:application/json")
  test -z "$json" && return 1
  version=$(echo "$json" | tr -s '\n' ' ' | sed 's/.*"tag_name":"//' | sed 's/".*//')
  test -z "$version" && return 1
  echo "$version"
}

cat /dev/null <<EOF
------------------------------------------------------------------------
End of functions from https://github.com/client9/shlib
------------------------------------------------------------------------
EOF

OWNER=ovh
REPO="sigstore-kms-ovhcloud"
BINARY=sigstore-kms-ovhcloud
FORMAT=tar.gz
OS=$(uname_os)
ARCH=$(uname_arch)
PREFIX="$OWNER/$REPO"

# use in logging routines
log_prefix() {
	echo "$PREFIX"
}

GITHUB_DOWNLOAD=https://github.com/${OWNER}/${REPO}/releases/download

uname_os_check "$OS"

parse_args "$@"

tag_to_version

adjust_format

log_info "found version: ${VERSION} for ${TAG}/${OS}/${ARCH}"

NAME=${REPO}_${VERSION}_${OS}_${ARCH}
TARBALL=${NAME}.${FORMAT}
TARBALL_URL=${GITHUB_DOWNLOAD}/${TAG}/${TARBALL}

execute
