/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hal_version_manager.h"

#include <android/hidl/manager/1.2/IServiceManager.h>
#include <base/logging.h>
#include <hidl/ServiceManagement.h>

#include <memory>

namespace bluetooth {
namespace audio {

std::unique_ptr<HalVersionManager> HalVersionManager::instance_ptr =
    std::make_unique<HalVersionManager>();

BluetoothAudioHalVersion HalVersionManager::GetHalVersion() {
  std::lock_guard<std::mutex> guard(instance_ptr->mutex_);
  return instance_ptr->hal_version_;
}

BluetoothAudioHalTransport HalVersionManager::GetHalTransport() {
  switch (GetHalVersion()) {
    case BluetoothAudioHalVersion::VERSION_AIDL_V1:
      return BluetoothAudioHalTransport::AIDL;
    case BluetoothAudioHalVersion::VERSION_2_0:
    case BluetoothAudioHalVersion::VERSION_2_1:
    case BluetoothAudioHalVersion::VERSION_2_2:
      return BluetoothAudioHalTransport::HIDL;
    default:
      return BluetoothAudioHalTransport::UNKNOWN;
  }
}

android::sp<IBluetoothAudioProvidersFactory_2_2>
HalVersionManager::GetProvidersFactory_2_2() {
  std::lock_guard<std::mutex> guard(instance_ptr->mutex_);
  if (instance_ptr->hal_version_ != BluetoothAudioHalVersion::VERSION_2_2) {
    return nullptr;
  }
  android::sp<IBluetoothAudioProvidersFactory_2_2> providers_factory =
      IBluetoothAudioProvidersFactory_2_2::getService();
  CHECK(providers_factory)
      << "V2_2::IBluetoothAudioProvidersFactory::getService() failed";

  LOG(INFO) << "V2_2::IBluetoothAudioProvidersFactory::getService() returned "
            << providers_factory.get()
            << (providers_factory->isRemote() ? " (remote)" : " (local)");
  return providers_factory;
}

android::sp<IBluetoothAudioProvidersFactory_2_1>
HalVersionManager::GetProvidersFactory_2_1() {
  std::lock_guard<std::mutex> guard(instance_ptr->mutex_);
  if (instance_ptr->hal_version_ != BluetoothAudioHalVersion::VERSION_2_1) {
    return nullptr;
  }
  android::sp<IBluetoothAudioProvidersFactory_2_1> providers_factory =
      IBluetoothAudioProvidersFactory_2_1::getService();
  CHECK(providers_factory)
      << "V2_1::IBluetoothAudioProvidersFactory::getService() failed";

  LOG(INFO) << "V2_1::IBluetoothAudioProvidersFactory::getService() returned "
            << providers_factory.get()
            << (providers_factory->isRemote() ? " (remote)" : " (local)");
  return providers_factory;
}

android::sp<IBluetoothAudioProvidersFactory_2_0>
HalVersionManager::GetProvidersFactory_2_0() {
  std::unique_lock<std::mutex> guard(instance_ptr->mutex_);
  if (instance_ptr->hal_version_ == BluetoothAudioHalVersion::VERSION_2_1) {
    guard.unlock();
    return instance_ptr->GetProvidersFactory_2_1();
  }
  android::sp<IBluetoothAudioProvidersFactory_2_0> providers_factory =
      IBluetoothAudioProvidersFactory_2_0::getService();
  CHECK(providers_factory)
      << "V2_0::IBluetoothAudioProvidersFactory::getService() failed";

  LOG(INFO) << "V2_0::IBluetoothAudioProvidersFactory::getService() returned "
            << providers_factory.get()
            << (providers_factory->isRemote() ? " (remote)" : " (local)");
  guard.unlock();
  return providers_factory;
}

HalVersionManager::HalVersionManager() {
  auto service_manager = android::hardware::defaultServiceManager1_2();
  CHECK(service_manager != nullptr);
  size_t instance_count = 0;
  auto listManifestByInterface_cb =
      [&instance_count](
          const hidl_vec<android::hardware::hidl_string>& instanceNames) {
        instance_count = instanceNames.size();
      };
  auto hidl_retval = service_manager->listManifestByInterface(
      kFullyQualifiedInterfaceName_2_2, listManifestByInterface_cb);
  if (!hidl_retval.isOk()) {
    LOG(FATAL) << __func__ << ": IServiceManager::listByInterface failure: "
               << hidl_retval.description();
    return;
  }

  if (instance_count > 0) {
    hal_version_ = BluetoothAudioHalVersion::VERSION_2_2;
    return;
  }

  hidl_retval = service_manager->listManifestByInterface(
      kFullyQualifiedInterfaceName_2_1, listManifestByInterface_cb);
  if (!hidl_retval.isOk()) {
    LOG(FATAL) << __func__ << ": IServiceManager::listByInterface failure: "
               << hidl_retval.description();
    return;
  }

  if (instance_count > 0) {
    hal_version_ = BluetoothAudioHalVersion::VERSION_2_1;
    return;
  }

  hidl_retval = service_manager->listManifestByInterface(
      kFullyQualifiedInterfaceName_2_0, listManifestByInterface_cb);
  if (!hidl_retval.isOk()) {
    LOG(FATAL) << __func__ << ": IServiceManager::listByInterface failure: "
               << hidl_retval.description();
    return;
  }

  if (instance_count > 0) {
    hal_version_ = BluetoothAudioHalVersion::VERSION_2_0;
    return;
  }

  hal_version_ = BluetoothAudioHalVersion::VERSION_UNAVAILABLE;
  LOG(ERROR) << __func__ << " No supported HAL version";
}

}  // namespace audio
}  // namespace bluetooth
