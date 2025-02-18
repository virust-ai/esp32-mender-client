const SOC_MMU_VADDR_MASK: u32 = 0x3FFFFF;
const SOC_MMU_INVALID: u32 = 1 << 8;
const MMU_LL_PSRAM_ENTRY_START_ID: u32 = 1152;
const SOC_IRAM0_CACHE_ADDRESS_LOW: u32 = 0x400D0000;
const SOC_IRAM0_CACHE_ADDRESS_HIGH: u32 = 0x40400000;
const SOC_IRAM1_CACHE_ADDRESS_LOW: u32 = 0x40400000;
const SOC_IRAM1_CACHE_ADDRESS_HIGH: u32 = 0x40800000;
const SOC_IROM0_CACHE_ADDRESS_LOW: u32 = 0x40800000;
const SOC_IROM0_CACHE_ADDRESS_HIGH: u32 = 0x40C00000;
const SOC_DRAM1_CACHE_ADDRESS_LOW: u32 = 0x3F800000;
const SOC_DRAM1_CACHE_ADDRESS_HIGH: u32 = 0x3FC00000;
const SOC_DROM0_CACHE_ADDRESS_LOW: u32 = 0x3F400000;
const SOC_DROM0_CACHE_ADDRESS_HIGH: u32 = 0x3F800000;
const DPORT_PRO_FLASH_MMU_TABLE: u32 = 0x3FF10000;

pub fn mmu_ll_get_page_size(_mmu_id: u32) -> u32 {
    super::super::mmu_hal::MMU_PAGE_64KB
}

pub fn mmu_ll_get_entry_id(_mmu_id: u32, vaddr: u32) -> u32 {
    let mut offset = 0;
    let mut shift_code = 0;
    let mut vaddr_mask = 0;

    if soc_address_in_bus!(SOC_DROM0_CACHE, vaddr) {
        offset = 0;
        shift_code = 16;
        vaddr_mask = SOC_MMU_VADDR_MASK;
    } else if soc_address_in_bus!(SOC_IRAM0_CACHE, vaddr) {
        offset = 64;
        shift_code = 16;
        vaddr_mask = SOC_MMU_VADDR_MASK;
    } else if soc_address_in_bus!(SOC_IRAM1_CACHE, vaddr) {
        offset = 128;
        shift_code = 16;
        vaddr_mask = SOC_MMU_VADDR_MASK;
    } else if soc_address_in_bus!(SOC_IROM0_CACHE, vaddr) {
        offset = 192;
        shift_code = 16;
        vaddr_mask = SOC_MMU_VADDR_MASK;
    } else if soc_address_in_bus!(SOC_DRAM1_CACHE, vaddr) {
        offset = MMU_LL_PSRAM_ENTRY_START_ID;
        shift_code = 15;
        vaddr_mask = SOC_MMU_VADDR_MASK >> 1;
    } else {
        #[cfg(feature = "log")]
        log::error!("mmu_ll_get_entry_id failed!");
    }

    offset + ((vaddr & vaddr_mask) >> shift_code)
}

pub fn mmu_ll_entry_id_to_paddr_base(_mmu_id: u32, entry_id: u32) -> u32 {
    let level = unsafe { dport_interrupt_disable() };
    let mmu_val = unsafe { *(DPORT_PRO_FLASH_MMU_TABLE as *const u32).offset(entry_id as isize) };
    unsafe { dport_interrupt_restore(level) };

    if entry_id >= MMU_LL_PSRAM_ENTRY_START_ID {
        mmu_val << 15
    } else {
        mmu_val << 16
    }
}

pub fn mmu_ll_check_entry_valid(_mmu_id: u32, entry_id: u32) -> bool {
    let level = unsafe { dport_interrupt_disable() };
    let mmu_val = unsafe { *(DPORT_PRO_FLASH_MMU_TABLE as *const u32).offset(entry_id as isize) };
    unsafe { dport_interrupt_restore(level) };

    (mmu_val & SOC_MMU_INVALID) == 0
}

// NOTE:Idk if required!
// Only used when using second core etc.

const SOC_DPORT_WORKAROUND_DIS_INTERRUPT_LVL: u32 = 5;
#[inline(always)]
unsafe fn dport_interrupt_disable() -> u32 {
    let level: u32;
    core::arch::asm!(
        "rsil {0}, {1}",
        out(reg) level,
        const SOC_DPORT_WORKAROUND_DIS_INTERRUPT_LVL,
        options(nomem, nostack)
    );
    level
}

#[inline(always)]
unsafe fn dport_interrupt_restore(level: u32) {
    core::arch::asm!(
        "wsr.ps {0}; rsync",
        in(reg) level,
        options(nomem, nostack)
    );
}
