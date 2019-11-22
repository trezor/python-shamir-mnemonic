#!/usr/bin/env bash

# See https://vaneyckt.io/posts/safer_bash_scripts_with_set_euxo_pipefail/
set -o errexit -o errtrace -o nounset -o pipefail

MASTER_SECRET='bb54aac4b89dc868ba37d9cc21b2cece'
MNEMONICS_2OF3=(
  'shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed'
  'shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking'
)

echo_bold() {
  local bold normal
  bold="$(tput bold)"
  normal="$(tput sgr0)"
  echo "${bold}${*}${normal}"
}

echo_error() {
  local error normal
  # Red color
  error="$(tput setaf 1)"
  normal="$(tput sgr0)"
  echo >&2 "${error}${*}${normal}"
}

run_tests() {
  if ! command -v shamir > /dev/null; then
    echo 'shamir executable not found'
    exit 1
  fi
  echo_bold 'Starting CLI tests for runtime errors (NOT testing correctness)'
  local status=0
  echo_bold 'Testing create 2of3...'
  (shamir create 2of4 > /dev/null) || status=1
  echo_bold 'Testing create 2of3 with user provided secret...'
  (shamir create 2of4 --master-secret "${MASTER_SECRET}" > /dev/null) || status=1
  echo_bold 'Testing create 2of3 with user provided secret and passphrase...'
  (shamir create 2of4 --master-secret "${MASTER_SECRET}" --passphrase 'TREZOR' > /dev/null) || status=1
  echo_bold 'Testing recovery...'
  (printf '%s\n' "${MNEMONICS_2OF3[@]}" | shamir recover > /dev/null) || status=1
  return "${status}"
}

main() {
  if ! run_tests; then
    echo_error 'Some of the tests failed! see above for the failed tests.'
    exit 1
  fi
  echo_bold 'All tests passed!'
}

main "$@"
