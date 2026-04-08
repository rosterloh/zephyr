/*
 * Copyright (c) 2026 Texas Instruments Incorporated
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file flsopskd_wrapper.h
 * @brief Wrapper functions for FLSOPSKD flash operations from MCU_PLUS_SDK
 */

#include <stdio.h>
#include <stdint.h>

/** @brief Initialize flsopskd wrapper module */
void flsopskd_wrapper_init(void);

/** @brief De-initialize flsopskd wrapper module */
void flsopskd_wrapper_deinit(void);

/**
 * @brief Write to flash using flsopskd wrapper module.
 *
 * CONFIG_FLSOPSKD_INT_MODE determines whether the API uses busy polling
 * or interrupt based mechanism to track write completion.
 *
 * @param data pointer to data buffer
 * @param length number of bytes to write
 * @param offset flash offset address
 * @return 0 on success, negative errno on failure
 */
int flsopskd_wrapper_write(uint8_t *data, uint32_t length, uint32_t offset);

/**
 * @brief Erase flash using flsopskd wrapper module.
 *
 * @param offset flash offset address
 * @param length number of bytes to erase
 * @return 0 on success, negative errno on failure
 */
int flsopskd_wrapper_erase(uint32_t offset, uint32_t length);

/**
 * @brief Check write completion status.
 *
 * @return 0 if write is complete, -EIO if write is in progress
 */
int flsopskd_wrapper_write_status(void);
