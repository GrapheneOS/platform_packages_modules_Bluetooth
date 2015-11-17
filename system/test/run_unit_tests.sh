#!/usr/bin/env bash

CR=$'\n'

known_tests=(
  net_test_btcore
  net_test_device
  net_test_hci
  net_test_osi
)

usage() {
  echo "Usage: $0 [-s <specific device> ][--all|--help|<test names>]"
  echo ""
  echo "Known test names:"

  for name in ${known_tests[*]}
  do
    echo "    $name"
  done
}

run_tests() {
  adb="adb${1:+ -s $1}"
  shift

  failed_tests=''
  for name in $*
  do
    echo "--- $name ---"
    echo "pushing..."
    $adb push {$ANDROID_PRODUCT_OUT,}/data/nativetest/$name/$name
    echo "running..."
    $adb shell data/nativetest/$name/$name
    if [ $? != 0 ]; then
      failed_tests="$failed_tests$CR!!! FAILED TEST: $name !!!";
    fi
  done

  if [ "$failed_tests" != "" ]; then
    echo "$failed_tests";
  fi
}

tests=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -s)
      shift
      if [ $# -eq 0 ]; then
        echo "error: no device specified" 1>&2
        usage
        exit 1
      fi
      device="$1"
      shift
      ;;
    --all)
      tests+=( ${known_tests[*]} )
      shift
      ;;
    *)
      tests+=( $1 )
      shift
      ;;
  esac
done

if [ ${#tests[*]} -eq 0 ]; then
  run_tests "$device" ${known_tests[*]}
else
  run_tests "$device" ${tests[*]}
fi
