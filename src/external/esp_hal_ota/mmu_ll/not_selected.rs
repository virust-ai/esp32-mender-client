pub fn mmu_ll_get_page_size(_mmu_id: u32) -> u32 {
    0
}

pub fn mmu_ll_get_entry_id(_mmu_id: u32, _vaddr: u32) -> u32 {
    0
}

pub fn mmu_ll_entry_id_to_paddr_base(_mmu_id: u32, _entry_id: u32) -> u32 {
    0
}

pub fn mmu_ll_check_entry_valid(_mmu_id: u32, _entry_id: u32) -> bool {
    false
}
