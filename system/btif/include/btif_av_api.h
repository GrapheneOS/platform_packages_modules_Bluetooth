/******************************************************************************
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/*****************************************************************************
 **
 **  Name:           btif_av_api.h
 **
 **  Description:    This is the public interface file for the advanced
 **                  audio/video streaming (AV) subsystem of BTIF, Broadcom's
 **                  Bluetooth application layer for mobile phones.
 **
 *****************************************************************************/

#ifndef BTIF_AV_API_H
#define BTIF_AV_API_H

#include "bt_target.h"
#include "bta_av_api.h"
#include "uipc.h"

#include "btif_media.h"
#include "a2d_api.h"


/*****************************************************************************
 **  Constants and data types
 *****************************************************************************/

#define BTIF_AV_FEEDING_ASYNCHRONOUS 0   /* asynchronous feeding, use tx av timer */
#define BTIF_AV_FEEDING_SYNCHRONOUS  1   /* synchronous feeding, no av tx timer */
typedef uint8_t tBTIF_AV_FEEDING_MODE;

/**
 * Structure used to configure the AV codec capabilities/config
 */
typedef struct
{
    tA2D_AV_CODEC_ID id;            /* Codec ID (TODO: to be removed) */
    uint8_t info[AVDT_CODEC_SIZE];     /* Codec info (can be config or capabilities) */
} tBTIF_AV_CODEC_INFO;

#endif /* BTIF_AV_API_H */
