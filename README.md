# Fluoride Bluetooth stack

## Building and running on AOSP
Just build AOSP - Fluoride is there by default.

## Building and running on Linux

Instructions for Ubuntu, tested on 14.04 with Clang 3.5.0 and 16.10 with Clang
 3.8.0

### Install required libraries

```sh
sudo apt-get install libevent-dev libc++-dev libc++abi-dev
```

### Install build tools

  - Install [ninja](https://ninja-build.org/) build system

```sh
sudo apt-get install ninja-build
```

or download binary from https://github.com/ninja-build/ninja/releases

  - Install [gn](https://chromium.googlesource.com/chromium/src/tools/gn/) -
 meta-build system that generates NinjaBuild files.

Get sha1 of current version from [here](
https://chromium.googlesource.com/chromium/buildtools/+/master/linux64/gn.sha1)
 and then download corresponding executable:

```sh
wget -O gn http://storage.googleapis.com/chromium-gn/<gn.sha1>
```

i.e. if sha1 is "3491f6687bd9f19946035700eb84ce3eed18c5fa" (value from 24 Feb
 2016) do

```sh
wget -O gn http://storage.googleapis.com/chromium-gn/3491f6687bd9f19946035700eb84ce3eed18c5fa
```

Then make binary executable and put it on your PATH, i.e.:

```sh
chmod a+x ./gn
sudo mv ./gn /usr/bin
```

### Download source

```sh
mkdir ~/fluoride
cd ~/fluoride
git clone https://android.googlesource.com/platform/packages/modules/Bluetooth/system
```

Then fetch third party dependencies:

```sh
cd ~/fluoride/bt
mkdir third_party
cd third_party
git clone https://github.com/google/googletest.git
git clone https://android.googlesource.com/platform/external/libchrome
git clone https://android.googlesource.com/platform/external/modp_b64
git clone https://android.googlesource.com/platform/external/tinyxml2
git clone https://android.googlesource.com/platform/hardware/libhardware
```

And third party dependencies of third party dependencies:

```sh
cd fluoride/bt/third_party/libchrome/base/third_party
mkdir valgrind
cd valgrind
curl https://chromium.googlesource.com/chromium/src/base/+/master/third_party/valgrind/valgrind.h?format=TEXT | base64 -d > valgrind.h
curl https://chromium.googlesource.com/chromium/src/base/+/master/third_party/valgrind/memcheck.h?format=TEXT | base64 -d > memcheck.h
```

NOTE: If packages/modules/Bluetooth/system is checked out under AOSP, then create symbolic links instead
of downloading sources

```
cd packages/modules/Bluetooth/system
mkdir third_party
cd third_party
ln -s ../../../external/libchrome libchrome
ln -s ../../../external/modp_b64 modp_b64
ln -s ../../../external/tinyxml2 tinyxml2
ln -s ../../../hardware/libhardware libhardware
ln -s ../../../external/googletest googletest
```

### Generate your build files

```sh
cd ~/fluoride/bt
gn gen out/Default
```

### Build

```sh
cd ~/fluoride/bt
ninja -C out/Default all
```

This will build all targets (the shared library, executables, tests, etc) and
 put them in out/Default. To build an individual target, replace "all" with the
 target of your choice, e.g. ```ninja -C out/Default net_test_osi```.

### Run

```sh
cd ~/fluoride/bt/out/Default
LD_LIBRARY_PATH=./ ./bluetoothtbd -create-ipc-socket=fluoride
```

### Eclipse IDE Support

1. Follows the Chromium project
 [Eclipse Setup Instructions](https://chromium.googlesource.com/chromium/src/+/master/docs/linux_eclipse_dev.md)
 until "Optional: Building inside Eclipse" section (don't do that section, we
 will set it up differently)

2. Generate Eclipse settings:

  ```sh
  cd packages/modules/Bluetooth/system
  gn gen --ide=eclipse out/Default
  ```

3. In Eclipse, do File->Import->C/C++->C/C++ Project Settings, choose the XML
 location under packages/modules/Bluetooth/system/out/Default

4. Right click on the project. Go to Preferences->C/C++ Build->Builder Settings.
 Uncheck "Use default build command", but instead using "ninja -C out/Default"

5. Goto Behaviour tab, change clean command to "-t clean"

