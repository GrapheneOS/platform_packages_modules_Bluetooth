#!/usr/bin/env bash
_USAGE="avatar [OPTIONS] <COMMAND> ...
  OPTIONS:
    -h, --help           Show this message and exit.
  COMMANDS:
    help                 Show this message and exit.
    format [FILES..]     Format python test files.
                         Files in 'p/m/B/android/pandora/test/*.py' are included by default.
    lint [FILES..]       Lint python test files.
                         Files in 'p/m/B/android/pandora/test/*.py' are included by default.
    run [OPTIONS..]      Run avatar tests through tradefed.
      OPTIONS: (subset, see 'avatar run --help-all')
        --include-filter=<ClassA[#test_a]>
                         Add a test filter in form of 'ClassA[#test_a]'.
        --test-bed       Set mobly test bed (default is 'android.bumbles').
        --mobly-std-log  Print mobly logs to standard outputs.
        --mobly-options=<'--opt-a --opt-b'>
                         Pass additional options to mobly, like '--verbose' or '--list'.
        ...              All other tradefed options, like '--log-level VERBOSE'.
                         See 'avatar run --help-all'
    "

_BT_ROOT="${ANDROID_BUILD_TOP}/packages/modules/Bluetooth"
_TEST_ROOT="${_BT_ROOT}/android/pandora/test"
_PY_SOURCES=(
  "${ANDROID_BUILD_TOP}/external/pandora/avatar/"{avatar,examples}
  "${_BT_ROOT}/pandora/server/bumble_experimental"
  "${_TEST_ROOT}/"*_test.py
  "${_TEST_ROOT}/main.py"
)

_PANDORA_PYTHON_PATHS=(
  "${_BT_ROOT}/pandora/server/"
  "${ANDROID_BUILD_TOP}/external/pandora/avatar/"
  "${ANDROID_BUILD_TOP}/external/python/bumble/"
  "${ANDROID_BUILD_TOP}/external/python/mobly/"
  "${ANDROID_BUILD_TOP}/external/python/pyee/"
  "${ANDROID_BUILD_TOP}/out/soong/.intermediates/external/pandora/bt-test-interfaces/python/pandora-python-gen-src/gen/"
  "${ANDROID_BUILD_TOP}/out/soong/.intermediates/packages/modules/Bluetooth/pandora/interfaces/python/pandora_experimental-python-gen-src/gen/"
)

case "$1" in
  'format') shift
    pip install \
      'black==22.10.0' \
      'isort==5.12.0'
    black -S -l 119 "$@" "${_PY_SOURCES[@]}"
    isort --profile black -l 119 --ds --lbt 1 --ca "$@" "${_PY_SOURCES[@]}"
  ;;
  'lint') shift
    pip install \
      'grpcio==1.51.1' \
      'protobuf==4.21.0' \
      'pyright==1.1.298' \
      'mypy==1.1.1' \
      'types-protobuf==4.21.0.3'
    export PYTHONPATH="$(IFS=:; echo "${_PANDORA_PYTHON_PATHS[*]}"):${PYTHONPATH}"
    mypy \
      --pretty --show-column-numbers --strict --no-warn-unused-ignores --ignore-missing-imports \
      "$@" "${_PY_SOURCES[@]}" || exit 1
    pyright \
      -p "${_TEST_ROOT}" \
      "$@" "${_PY_SOURCES[@]}"
  ;;
  'run') shift
    tradefed.sh \
      run commandAndExit template/local_min --template:map test=avatar --log-level INFO \
      "$@"
  ;;
  'help'|'--help'|'-h') shift
    echo "${_USAGE}"
    exit 0
  ;;
  '')
    echo "no command provided (try help)"
    echo "${_USAGE}"
    exit 1
  ;;
  *)
    echo "$1: invalid command (try help)"
    echo "${_USAGE}"
    exit 1
  ;;
esac
