const SOC_MMU_VADDR_MASK: u32 = 0x3FFFFF;
const DR_REG_MMU_TABLE: u32 = 0x61801000;
const SOC_MMU_VALID_VAL_MASK: u32 = 0x3fff;
const SOC_MMU_INVALID: u32 = 1 << 14;
const SOC_IRAM0_CACHE_ADDRESS_LOW: u32 = 0x40080000;
const SOC_IRAM0_CACHE_ADDRESS_HIGH: u32 = 0x40400000;
const SOC_IRAM1_ADDRESS_LOW: u32 = 0x40400000;
const SOC_IRAM1_ADDRESS_HIGH: u32 = 0x40800000;
const SOC_DROM0_ADDRESS_LOW: u32 = 0x3f000000;
const SOC_DROM0_ADDRESS_HIGH: u32 = 0x3f400000;
const SOC_DRAM0_CACHE_ADDRESS_LOW: u32 = 0x3fc00000;
const SOC_DRAM0_CACHE_ADDRESS_HIGH: u32 = 0x3ff80000;
const SOC_DRAM1_ADDRESS_LOW: u32 = 0x3f800000;
const SOC_DRAM1_ADDRESS_HIGH: u32 = 0x3fc00000;
const SOC_DPORT_CACHE_ADDRESS_LOW: u32 = 0x3f500000;
const SOC_DPORT_CACHE_ADDRESS_HIGH: u32 = 0x3f800000;
const PRO_CACHE_IBUS0_MMU_START: u32 = 0;
const PRO_CACHE_IBUS1_MMU_START: u32 = 0x100;
const PRO_CACHE_IBUS2_MMU_START: u32 = 0x200;
const PRO_CACHE_DBUS0_MMU_START: u32 = 0x300;
const PRO_CACHE_DBUS1_MMU_START: u32 = 0x400;
const PRO_CACHE_DBUS2_MMU_START: u32 = 0x500;

pub fn mmu_ll_get_page_size(_mmu_id: u32) -> u32 {
    super::super::mmu_hal::MMU_PAGE_64KB
}

pub fn mmu_ll_get_entry_id(_mmu_id: u32, vaddr: u32) -> u32 {
    let offset = if soc_address_in_bus!(SOC_DROM0, vaddr) {
        PRO_CACHE_IBUS2_MMU_START / 4
    } else if soc_address_in_bus!(SOC_IRAM0_CACHE, vaddr) {
        PRO_CACHE_IBUS0_MMU_START / 4
    } else if soc_address_in_bus!(SOC_IRAM1, vaddr) {
        PRO_CACHE_IBUS1_MMU_START / 4
    } else if soc_address_in_bus!(SOC_DPORT_CACHE, vaddr) {
        PRO_CACHE_DBUS2_MMU_START / 4
    } else if soc_address_in_bus!(SOC_DRAM1, vaddr) {
        PRO_CACHE_DBUS1_MMU_START / 4
    } else if soc_address_in_bus!(SOC_DRAM0_CACHE, vaddr) {
        PRO_CACHE_DBUS0_MMU_START / 4
    } else {
        #[cfg(feature = "log")]
        log::error!("mmu_ll_get_entry_id failed!");

        0
    };

    offset + ((vaddr & SOC_MMU_VADDR_MASK) >> 16)
}

pub fn mmu_ll_entry_id_to_paddr_base(_mmu_id: u32, entry_id: u32) -> u32 {
    let ptr = (DR_REG_MMU_TABLE + entry_id * 4) as *const u32;
    unsafe { ((*ptr) & SOC_MMU_VALID_VAL_MASK) << 16 }
}

pub fn mmu_ll_check_entry_valid(_mmu_id: u32, entry_id: u32) -> bool {
    let ptr = (DR_REG_MMU_TABLE + entry_id * 4) as *const u32;
    unsafe { ((*ptr) & SOC_MMU_INVALID) == 0 }
}
