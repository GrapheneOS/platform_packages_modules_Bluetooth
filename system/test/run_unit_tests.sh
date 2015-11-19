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
  echo "       $0 [-i <iterations>] [-s <specific device>] [--all] [<test name>[.<filter>] ...] [--<arg> ...]"
  echo
  echo "Unknown long arguments are passed to the test."
  echo
  echo "Known test names:"

  for name in ${known_tests[*]}
  do
    echo "    $name"
  done
}

iterations=1
device=
tests=()
test_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -i)
      shift
      if [ $# -eq 0 ]; then
        echo "error: number of iterations expected" 1>&2
        usage
        exit 1
      fi
      iterations=$(( $1 ))
      shift
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

adb="adb${device:+ -s $device}"

failed_tests=''
for spec in ${tests[*]}
do
  name="${spec%%.*}"
  if [ "${name}" != "${spec}" ]; then
    filter="${spec#*.}"
  fi
  echo "--- $name ---"
  echo "pushing..."
  $adb push {$ANDROID_PRODUCT_OUT,}/data/nativetest/$name/$name
  echo "running..."
  failed_count=0
  for i in $(seq 1 ${iterations})
  do
    $adb shell data/nativetest/$name/$name${filter:+ "--gtest_filter=${filter}"} ${test_args[*]} || failed_count=$(( $failed_count + 1 ))
  done

  if [ $failed_count != 0 ]; then
    failed_tests="$failed_tests$CR!!! FAILED TEST: $name ${failed_count}/${iterations} !!!";
  fi
done

if [ "$failed_tests" != "" ]; then
  echo "$failed_tests";
  exit 1
fi

exit 0
