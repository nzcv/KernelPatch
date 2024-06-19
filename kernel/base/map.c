/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "setup.h"

#define NUMA_NO_NODE (-1)

typedef uint64_t phys_addr_t;
typedef int (*memblock_reserve_f)(phys_addr_t base, phys_addr_t size);
typedef phys_addr_t (*memblock_phys_alloc_try_nid_f)(phys_addr_t size, phys_addr_t align, int nid);
typedef void *(*memblock_virt_alloc_try_nid_f)(phys_addr_t size, phys_addr_t align, phys_addr_t min_addr,
                                               phys_addr_t max_addr, int nid);
typedef int (*memblock_free_f)(phys_addr_t base, phys_addr_t size);
typedef int (*memblock_mark_nomap_f)(phys_addr_t base, phys_addr_t size);
typedef int (*printk_f)(const char *fmt, ...);
typedef void (*paging_init_f)(void);

map_data_t map_data __section(.map.data) __aligned(MAP_ALIGN) = {
#ifdef MAP_DEBUG
    .str_fmt_px = "KP: %x-%llx\n",
#endif
};

uint64_t __section(.map.text) __noinline __aligned(MAP_ALIGN) get_myva()
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    return this_va & ~((uint64_t)MAP_ALIGN - 1);
}

map_data_t *__noinline get_data()
{
    uint64_t va = get_myva() - sizeof(map_data_t);
    return (map_data_t *)(va & ~((uint64_t)MAP_ALIGN - 1));
}

static uint64_t __noinline get_kva()
{
    map_data_t *data = get_data();
    uint64_t kernel_va = (uint64_t)data - data->map_offset;
    return kernel_va; //0xffffff8008080000
}

static uint64_t __noinline phys_to_lm(map_data_t *data, uint64_t phys)
{
    return phys + data->linear_voffset;
}

static void flush_tlb_all()
{
    asm volatile("dsb ishst" : : : "memory");
    asm volatile("tlbi vmalle1is\n"
                 "dsb ish\n"
                 "tlbi vmalle1is\n");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static void __noinline flush_icache_all(void)
{
    asm volatile("dsb ish" : : : "memory");
    asm volatile("ic ialluis");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static map_data_t * __noinline mem_proc()
{
    // 文件布局可以知道.map.data和.map.text顺序排列. 拿到当前地址向上偏移sizeof(map_data_t)即可获取map_data_t.
    map_data_t *data = get_data();
    // 获取内核虚拟地址
    uint64_t kernel_va = get_kva();

    // 相关符号重定位
    // relocation
    data->kimage_voffset = kernel_va - data->kernel_pa;
    data->paging_init_relo += kernel_va;

    uint64_t map_symbol_addr = (uint64_t)&data->map_symbol;
    for (uint64_t addr = map_symbol_addr; addr < map_symbol_addr + MAP_SYMBOL_SIZE; addr += 8) {
        if (*(uint64_t *)addr) *(uint64_t *)addr += kernel_va;
    }

#ifdef MAP_DEBUG
    data->printk_relo += kernel_va;
#endif

    // pgtable
    uint64_t tcr_el1;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    uint64_t t1sz = tcr_el1 << 42 >> 58; // bits(tcr_el1, 21, 16)
    uint64_t va1_bits = 64 - t1sz;
    data->va1_bits = va1_bits;
    uint64_t tg1 = tcr_el1 << 32 >> 62; // bits(tcr_el1, 31, 30)
    /*
    /// Granule size for the TTBR1_EL1.
    ///
    /// 10 4KiB
    /// 01 16KiB
    /// 11 64KiB
    ///
    /// Other values are reserved.
    ///
    /// If the value is programmed to either a reserved value, or a size that has not been
    /// implemented, then the hardware will treat the field as if it has been programmed to an
    /// IMPLEMENTATION DEFINED choice of the sizes that has been implemented for all purposes
    /// other than the value read back from this register.
    ///
    /// It is IMPLEMENTATION DEFINED whether the value read back is the value programmed or the
    /// value that corresponds to the size chosen.
    TG1   OFFSET(30) NUMBITS(2) [
        KiB_4 = 0b10,
        KiB_16 = 0b01,
        KiB_64 = 0b11
    ],
    */
    uint64_t page_shift = 12;
    if (tg1 == 1) {
        page_shift = 14;
    } else if (tg1 == 3) {
        page_shift = 16;
    }
    data->page_shift = page_shift;

    // linear
    // ?????
    /*
    ROM:FFFFFF80092E0640 FD 7B BE A9                 STP             X29, X30, [SP,#-0x20+var_s0]!
    ....
    ROM:FFFFFF80092E0724 E1 03 00 AA                 MOV             X1, X0             //计算linear_voffset
    ROM:FFFFFF80092E0728 21 00 14 CB                 SUB             X1, X1, X20
    ROM:FFFFFF80092E072C 61 66 00 F9                 STR             X1, [X19,#0xC8]
    */
    uint64_t detect_phys = ((memblock_phys_alloc_try_nid_f)data->map_symbol.memblock_phys_alloc_relo)(0, 0x10, NUMA_NO_NODE);    
    uint64_t detect_virt = (uint64_t)((memblock_virt_alloc_try_nid_f)data->map_symbol.memblock_virt_alloc_relo)(
        0, 0x10, detect_phys, detect_phys, NUMA_NO_NODE);
    data->linear_voffset = detect_virt - detect_phys;

    return data;
}

// todo: 52-bits pa
static uint64_t __noinline get_or_create_pte(map_data_t *data, uint64_t va, uint64_t pa, uint64_t attr_indx)
{
    memblock_phys_alloc_try_nid_f memblock_phys_alloc_try_nid =
        (memblock_phys_alloc_try_nid_f)data->map_symbol.memblock_phys_alloc_relo;

    //页大小
    uint64_t page_shift = data->page_shift;
    //虚拟地址位数
    uint64_t va_bits = data->va1_bits;
    //????
    uint64_t page_level = (va_bits - 4) / (page_shift - 3);
    // 这里可以看一下文档
    // page_shift 和 Granule size相互对应的
    // 它会有一个规律:
    // 10 4KB
    //   9, 9,  9, 9, 12(48bit)
    // 01 16KB
    //  11,11, 11, 14(48bit)
    // 11 64KB
    //  12,13, 13, 16(48bit)
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;

    uint64_t ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    /*
    pub TTBR1_EL1 [
        /// An ASID for the translation table base address. The TCR_EL1.A1 field selects either
        /// TTBR0_EL1.ASID or TTBR1_EL1.ASID.
        ///
        /// If the implementation has only 8 bits of ASID, then the upper 8 bits of this field are
        /// RES 0.
        ASID  OFFSET(48) NUMBITS(16) [],

        /// Translation table base address
        BADDR OFFSET(1) NUMBITS(47) [],

        /// Common not Private
        CnP   OFFSET(0) NUMBITS(1) []
    ]
    */
    // 拿到页表起始位置
    uint64_t baddr = ttbr1_el1 & 0xFFFFFFFFFFFE;
    uint64_t page_size = 1 << page_shift;
    // 单页大小
    uint64_t page_size_mask = ~(page_size - 1);
    // https://github.com/astahl/picrust/blob/master/kernel/src/system/arm_core/mmu/descriptors.rs    
    uint64_t attr_prot = 0xC0000000000703 | attr_indx;

    uint64_t pxd_pa = baddr & page_size_mask;
    uint64_t pxd_va = phys_to_lm(data, pxd_pa);

    // L1, L2, L3
    // 
    uint64_t pxd_entry_va = 0;
    for (uint64_t lv = 4 - page_level; lv < 4; lv++) {
        //L2: pxd_shift = (16 - 3) * (4- 2) + 3 = 29
        //L2: uint64_t L2Mask = ((1L << 32) - 1) ^ ((1L << 29) -1);
        uint64_t pxd_shift = (page_shift - 3) * (4 - lv) + 3;        
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        uint64_t alloc_flag = 0;
        uint64_t block_flag = 0;
        //pxd_entry_va = pxd_va + pxd_index * sizeof(PAGE_DESC);
        pxd_entry_va = pxd_va + pxd_index * 8;

        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);

        if ((pxd_desc & 0b11) == 0b11) { // table
            //pxd output address
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift)) - 1) << page_shift);
        } else if ((pxd_desc & 0b11) == 0b01) { // block, or page
            // 4k page: lv1, lv2. 
            // 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_flag = 1;
        } else { // invalid, alloc            
            if (lv != 3) {
                pxd_pa = memblock_phys_alloc_try_nid(page_size, page_size, 0);
                alloc_flag = 1;
            } else {
                // 直接存储的就是偏移地址
                pxd_pa = pa;
            }
            // 赋予权限
            pxd_desc = (pxd_pa) | attr_prot;
            *((uint64_t *)pxd_entry_va) = pxd_desc;
        }
        // 如果新的内存分配, 清0处理
        pxd_va = phys_to_lm(data, pxd_pa);
        if (alloc_flag) {
            for (uint64_t i = pxd_va; i < pxd_va + page_size; i += 8) {
                *(uint64_t *)i = 0;
            }
        }
        if (block_flag) {
            break;
        }
    }
    // 返回页表项
    return pxd_entry_va;
}

// todo: bti
void __noinline _paging_init()
{
    map_data_t *data = mem_proc();
#ifdef MAP_DEBUG
    printk_f printk = (printk_f)(data->printk_relo);
#define map_debug(idx, val) printk(data->str_fmt_px, idx, val)
    for (int i = 0; i < sizeof(map_data_t); i += 8) {
        map_debug(i, *(uint64_t *)((uint64_t)data + i));
    }
#else
#define map_debug(idx, val)
#endif

    // 对kpimg 和 extra
    uint64_t page_size = 1 << data->page_shift;
    uint64_t old_start_pa = data->start_offset + data->kernel_pa;
    uint64_t reserve_size = data->start_img_size + data->extra_size;
    uint64_t align_extra_size = (data->extra_size + page_size - 1) & ~(page_size - 1);
    uint64_t all_size = data->start_size + align_extra_size + data->alloc_size;

    // 预留内存防止被paging_init覆盖掉
    // reserve old start
    ((memblock_reserve_f)data->map_symbol.memblock_reserve_relo)(old_start_pa, reserve_size);
    // alloc
    uint64_t start_pa =
        ((memblock_phys_alloc_try_nid_f)data->map_symbol.memblock_phys_alloc_relo)(all_size, page_size, 0);
    // mark all size nomap
    // 阻止操作系统将该内存用于常规操作或将其映射到虚拟地址空间
    if (data->map_symbol.memblock_mark_nomap_relo)
        ((memblock_mark_nomap_f)(data->map_symbol.memblock_mark_nomap_relo))(start_pa, all_size);

    // 跳转回去执行paging_init
    uint64_t paging_init_va = data->paging_init_relo;
    *(uint32_t *)(paging_init_va) = data->paging_init_backup;
    flush_icache_all();
    ((paging_init_f)(paging_init_va))();
    // can't write data below

    // AttrIndx[2:0] encoding
    uint64_t ktext_pte = get_or_create_pte(data, data->paging_init_relo, 0, 0);
    uint64_t attrs = *(uint64_t *)ktext_pte;
    uint64_t attr_indx = attrs & 0b11100;

    // clear wxn
    // todo: restore wxn later
    // https://github.com/rust-embedded/aarch64-cpu/blob/main/src/registers/sctlr_el1.rs
    // 0 This control has no effect on memory access permissions.
    uint64_t sctlr_el1 = 0;
    asm volatile("mrs %[reg], sctlr_el1" : [reg] "+r"(sctlr_el1));
    sctlr_el1 &= 0xFFFFFFFFFFF7FFFF;
    asm volatile("msr sctlr_el1, %[reg]" : : [reg] "r"(sctlr_el1));

    // move start memory
    uint64_t old_start_va = phys_to_lm(data, old_start_pa);

    // uint64_t vm_gurad_enough = page_size << 3;
    uint64_t start_va = start_pa + data->kimage_voffset;

    for (uint64_t off = 0; off < all_size; off += page_size) {
        uint64_t entry = get_or_create_pte(data, start_va + off, start_pa + off, attr_indx);
        *(uint64_t *)entry = (*(uint64_t *)entry | 0x8000000000000) & 0xFFDFFFFFFFFFFF7F;
    }
    flush_tlb_all();

    //clear memory
    for (uint64_t i = start_va; i < start_va + all_size; i += 8) {
        *(uint64_t *)i = 0;
    }
    //memcpy kpimg
    for (uint64_t i = 0; i < data->start_img_size; i += 8) {
        *(uint64_t *)(start_va + i) = *(uint64_t *)(old_start_va + i);
    }
    //memcpy extra
    for (uint64_t i = 0; i < data->extra_size; i += 8) {
        *(uint64_t *)(start_va + data->start_size + i) = *(uint64_t *)(old_start_va + data->start_img_size + i);
    }

    flush_icache_all();

    // free old start
    ((memblock_free_f)data->map_symbol.memblock_free_relo)(old_start_pa, reserve_size);

    // start
    ((start_f)start_va)(data->kimage_voffset, data->linear_voffset);
}
