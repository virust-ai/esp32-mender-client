const SOC_MMU_VADDR_MASK: u32 = 0x7FFFFF;
const DR_REG_MMU_TABLE: u32 = 0x600c5000;
const SOC_MMU_VALID_VAL_MASK: u32 = 0xff;
const SOC_MMU_INVALID: u32 = 1 << 8;

pub fn mmu_ll_get_page_size(_mmu_id: u32) -> u32 {
    super::super::mmu_hal::MMU_PAGE_64KB
}

pub fn mmu_ll_get_entry_id(_mmu_id: u32, vaddr: u32) -> u32 {
    (vaddr & SOC_MMU_VADDR_MASK) >> 16
}

pub fn mmu_ll_entry_id_to_paddr_base(_mmu_id: u32, entry_id: u32) -> u32 {
    let ptr = (DR_REG_MMU_TABLE + entry_id * 4) as *const u32;
    unsafe { ((*ptr) & SOC_MMU_VALID_VAL_MASK) << 16 }
}

pub fn mmu_ll_check_entry_valid(_mmu_id: u32, entry_id: u32) -> bool {
    let ptr = (DR_REG_MMU_TABLE + entry_id * 4) as *const u32;
    unsafe { ((*ptr) & SOC_MMU_INVALID) == 0 }
}
