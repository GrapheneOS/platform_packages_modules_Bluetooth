/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */
/*******************************************************************************
 *
 *  Filename:      bluetooth_adv_audio.h
 *
 *  Description:   Main API header file for LEA interfacing
 *
 ******************************************************************************/

#pragma once

/*******************************************************************************
 *  TInterface APIs
 ******************************************************************************/

const void* get_adv_audio_profile_interface(const char* profile_id);
void init_adv_audio_interfaces();
