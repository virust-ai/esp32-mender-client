#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};

#[allow(dead_code)]
pub const MMU_PAGE_8KB: u32 = 0x2000;
pub const MMU_PAGE_16KB: u32 = 0x4000;
pub const MMU_PAGE_32KB: u32 = 0x8000;
pub const MMU_PAGE_64KB: u32 = 0x10000;

fn mmu_hal_pages_to_bytes(mmu_id: u32, page_num: u32) -> u32 {
    let mmu_page_size = super::mmu_ll::mmu_ll_get_page_size(mmu_id);
    let shift_code = match mmu_page_size {
        MMU_PAGE_64KB => 16,
        MMU_PAGE_32KB => 15,

        MMU_PAGE_16KB => 14,
        _ => panic!("WRONG MMU_PAGE_SIZE! 0x{:X?}", mmu_page_size),
    };

    page_num << shift_code
}

pub fn esp_get_current_running_partition(partitions: &[(u32, u32)]) -> Option<usize> {
    // NOTE:
    // mmu_id is always 0 because s_vaddr_to_paddr is using 0 for all targets
    // except esp32p4 (per SOC_MMU_PER_EXT_MEM_TARGET define)
    //
    // https://github.com/espressif/esp-idf/blob/b5ac4fbdf9e9fb320bb0a98ee4fbaa18f8566f37/components/esp_mm/esp_mmu_map.c#L754
    let mmu_id = 0;

    let ptr = esp_get_current_running_partition as *const () as *const u32;
    let entry_id = super::mmu_ll::mmu_ll_get_entry_id(mmu_id, ptr as u32);

    if !super::mmu_ll::mmu_ll_check_entry_valid(mmu_id, entry_id) {
        log_error!("mmu_ll_check_entry_valid failed!");
        return None;
    }

    // page_num is always 1
    // https://github.com/espressif/esp-idf/blob/master/components/hal/mmu_hal.c#L129
    let page_size_in_bytes = mmu_hal_pages_to_bytes(mmu_id, 1);
    let offset = (ptr as u32) % page_size_in_bytes;

    let paddr_base = super::mmu_ll::mmu_ll_entry_id_to_paddr_base(mmu_id, entry_id);
    let paddr = paddr_base | offset;

    for (i, &part) in partitions.iter().enumerate() {
        if paddr >= part.0 && paddr < part.0 + part.1 {
            return Some(i);
        }
    }

    None
}
