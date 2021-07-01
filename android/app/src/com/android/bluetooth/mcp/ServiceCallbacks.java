/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

package com.android.bluetooth.mcp;

import android.bluetooth.BluetoothDevice;

/**
 * Media Control Profile service callback interface
 */
public interface ServiceCallbacks {
    public void onServiceInstanceRegistered(ServiceStatus status, McpService serviceProxy);
    public void onServiceInstanceUnregistered(ServiceStatus status);
    public void onMediaControlRequest(McpServiceMediaControlRequest request);
    public void onSearchRequest(McpServiceSearchRequest request);
    public void onSetObjectIdRequest(int objField, long objectId);
    public void onTrackPositionSetRequest(long position);
    public void onPlaybackSpeedSetRequest(float speed);
    public void onPlayingOrderSetRequest(int order);
    public void onCurrentTrackObjectIdSet(long objectId);
    public void onNextTrackObjectIdSet(long objectId);
    public void onCurrentGroupObjectIdSet(long objectId);
    public void onCurrentTrackMetadataRequest();
    public void onPlayerStateRequest(PlayerStateField[] stateFields);
    public long onGetFeatureFlags();
    public long onGetCurrentTrackPosition();
}
