/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "image.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "order.h"
#include "common.h"
#include "log.h"

#define EFI_MAGIC_SIG "MZ"
#define KERNEL_MAGIC "ARM\x64"

typedef struct
{
    union _entry
    {
        // #ifdef CONFIG_EFI
        struct _efi
        {
            uint8_t mz[4]; // "MZ" signature required by UEFI.
            uint32_t b_insn; // branch to kernel start, magic
        } efi;
        // #else
        struct _nefi
        {
            uint32_t b_insn; // branch to kernel start, magic
            uint32_t reserved0;
        } nefi;
        // #endif
    } hdr;

    uint64_t kernel_offset; // Image load load_offset from start of RAM, little-endian
    uint64_t kernel_size_le; // Effective size of kernel image, little-endian
    uint64_t kernel_flag_le; // Informative flags, little-endian

    uint64_t reserved0;
    uint64_t reserved1;
    uint64_t reserved2;

    char magic[4]; // Magic number "ARM\x64"

    union _pe
    {
        // #ifdef CONFIG_EFI
        uint64_t pe_offset; // Offset to the PE header.
        // #else
        uint64_t npe_reserved;
        // #endif
    } pe;
} arm64_hdr_t;

/**
读取kenrel header信息
*/
int32_t get_kernel_info(kernel_info_t *kinfo, const char *img, int32_t imglen)
{
    kinfo->is_be = 0;

    arm64_hdr_t *khdr = (arm64_hdr_t *)img;
    if (strncmp(khdr->magic, KERNEL_MAGIC, strlen(KERNEL_MAGIC))) {
        tools_loge_exit("kernel image magic error: %s\n", khdr->magic);
    }

    kinfo->uefi = !strncmp((const char *)khdr->hdr.efi.mz, EFI_MAGIC_SIG, strlen(EFI_MAGIC_SIG));

    // 主入口指令
    uint32_t b_primary_entry_insn;
    // 主入口指令偏移
    uint32_t b_stext_insn_offset;
    if (kinfo->uefi) {
        b_primary_entry_insn = khdr->hdr.efi.b_insn;
        b_stext_insn_offset = 4;
    } else {
        b_primary_entry_insn = khdr->hdr.nefi.b_insn;
        b_stext_insn_offset = 0;
    }
    kinfo->b_stext_insn_offset = b_stext_insn_offset;

    b_primary_entry_insn = u32le(b_primary_entry_insn);
    if ((b_primary_entry_insn & 0xFC000000) != 0x14000000) {
        tools_loge_exit("kernel primary entry: %x\n", b_primary_entry_insn);
    } else {
        uint32_t imm = (b_primary_entry_insn & 0x03ffffff) << 2;
        kinfo->primary_entry_offset = imm + b_stext_insn_offset;
    }

    kinfo->load_offset = u64le(khdr->kernel_offset);
    kinfo->kernel_size = u64le(khdr->kernel_size_le);

    uint8_t flag = u64le(khdr->kernel_flag_le) & 0x0f;
    kinfo->is_be = flag & 0x01;

    if (kinfo->is_be) tools_loge_exit("kernel unexpected arm64 big endian img\n");

    switch ((flag & 0b0110) >> 1) {
    case 2: // 16k
        kinfo->page_shift = 14;
        break;
    case 3: // 64k
        kinfo->page_shift = 16;
        break;
    case 1: // 4k
    default:
        kinfo->page_shift = 12;
    }

    // kernel image_size: 0x025b0010
    tools_logi("kernel image_size: 0x%08x\n", imglen);
    // kernel uefi header: false
    tools_logi("kernel uefi header: %s\n", kinfo->uefi ? "true" : "false");
    // kernel load_offset: 0x80000
    tools_logi("kernel load_offset: 0x%08x\n", kinfo->load_offset);
    // kernel kernel_size: 02b44000
    tools_logi("kernel kernel_size: 0x%08x\n", kinfo->kernel_size);
    // kernel page_shift: 12
    tools_logi("kernel page_shift: %d\n", kinfo->page_shift);
    // kernel is_be: false
    tools_logi("kernel is_be: %x\n", kinfo->is_be);
    // kernel uefi: 0
    tools_logi("kernel uefi: %x\n", kinfo->uefi);
    // kernel load_offset: 80000
    tools_logi("kernel load_offset: %x\n", kinfo->load_offset);
    tools_logi("kernel kernel_size: %x\n", kinfo->kernel_size);
    tools_logi("kernel page_shift: %x\n", kinfo->page_shift);
    // kernel b_stext_insn_offset: 0
    tools_logi("kernel b_stext_insn_offset: %x\n", kinfo->b_stext_insn_offset);
    // kernel primary_entry_offset: 1f80000
    tools_logi("kernel primary_entry_offset: %x\n", kinfo->primary_entry_offset);
    return 0;
}

int32_t kernel_resize(kernel_info_t *kinfo, char *img, int32_t size)
{
    arm64_hdr_t *khdr = (arm64_hdr_t *)img;
    uint64_t ksize = size;
    if (is_be() ^ kinfo->is_be) ksize = u64swp(size);
    khdr->kernel_size_le = ksize;
    return 0;
}