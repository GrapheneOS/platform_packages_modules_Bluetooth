#!/usr/bin/env bash

CR=$'\n'

known_tests=(
  net_test_btcore
  net_test_device
  net_test_hci
  net_test_osi
)

usage() {
  echo "Usage: $0 --help"
  echo "       $0 [-s <specific device>] [--all] [<test name>[.<filter>] ...] [--<arg> ...]"
  echo
  echo "Unknown long arguments are passed to the test."
  echo
  echo "Known test names:"

  for name in ${known_tests[*]}
  do
    echo "    $name"
  done
}

run_tests() {
  adb="adb${1:+ -s $1}"
  shift

  test_args=()
  for arg
  do
    shift
    if [ "$arg" == "--" ]; then
      break
    else
      test_args+=( "$arg" )
    fi
  done

  failed_tests=''
  for spec in $*
  do
    name="${spec%%.*}"
    if [ "${name}" != "${spec}" ]; then
      filter="${spec#*.}"
    fi
    echo "--- $name ---"
    echo "pushing..."
    $adb push {$ANDROID_PRODUCT_OUT,}/data/nativetest/$name/$name
    echo "running..."
    $adb shell data/nativetest/$name/$name${filter:+ "--gtest_filter=${filter}"} ${test_args[*]}
    if [ $? != 0 ]; then
      failed_tests="$failed_tests$CR!!! FAILED TEST: $name !!!";
    fi
  done

  if [ "$failed_tests" != "" ]; then
    echo "$failed_tests";
    return 1
  fi
  return 0
}

tests=()
test_args=()
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
    --*)
      test_args+=( "$1" )
      shift
      ;;
    *)
      tests+=( $1 )
      shift
      ;;
  esac
done

if [ ${#tests[*]} -eq 0 ]; then
  tests+=( ${known_tests[*]} )
fi

run_tests "$device" ${test_args[*]} -- ${tests[*]} || exit 1
