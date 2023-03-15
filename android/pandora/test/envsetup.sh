function avatar {
  # avatar script.
  _AVATAR="${ANDROID_BUILD_TOP}/packages/modules/Bluetooth/android/pandora/test/avatar.sh"

  # only compile when needed.
  if [[ "$1" == "run" ]]; then
    m avatar avatar.sh PandoraServer tradefed
    _AVATAR="avatar.sh"
  fi

  # run avatar script.
  "${_AVATAR}" "$@"
}
