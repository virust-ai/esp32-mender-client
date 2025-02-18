use super::super::mmu_hal::{MMU_PAGE_16KB, MMU_PAGE_32KB, MMU_PAGE_64KB, MMU_PAGE_8KB};

const SOC_MMU_ENTRY_NUM: u32 = 256;
const SOC_MMU_VALID_VAL_MASK: u32 = 0x1ff;
const SOC_MMU_VALID: u32 = 1 << 9;

fn soc_mmu_vaddr_mask(mmu_id: u32) -> u32 {
    mmu_ll_get_page_size(mmu_id) * SOC_MMU_ENTRY_NUM - 1
}

pub fn mmu_ll_get_page_size(_mmu_id: u32) -> u32 {
    let spi_mem = unsafe { &*esp32h2::SPI0::ptr() };
    let page_size_code = spi_mem.mmu_power_ctrl().read().spi_mmu_page_size().bits();

    match page_size_code {
        0 => MMU_PAGE_64KB,
        1 => MMU_PAGE_32KB,
        2 => MMU_PAGE_16KB,
        _ => MMU_PAGE_8KB,
    }
}

pub fn mmu_ll_get_entry_id(mmu_id: u32, vaddr: u32) -> u32 {
    let shift_code = match mmu_ll_get_page_size(mmu_id) {
        MMU_PAGE_64KB => 16,
        MMU_PAGE_32KB => 15,
        MMU_PAGE_16KB => 14,
        MMU_PAGE_8KB => 13,
        _ => {
            #[cfg(feature = "log")]
            log::error!("mmu_ll_get_entry_id failed!");

            0
        }
    };

    (vaddr & soc_mmu_vaddr_mask(mmu_id)) >> shift_code
}

pub fn mmu_ll_entry_id_to_paddr_base(mmu_id: u32, entry_id: u32) -> u32 {
    let shift_code = match mmu_ll_get_page_size(mmu_id) {
        MMU_PAGE_64KB => 16,
        MMU_PAGE_32KB => 15,
        MMU_PAGE_16KB => 14,
        MMU_PAGE_8KB => 13,
        _ => {
            #[cfg(feature = "log")]
            log::error!("mmu_ll_entry_id_to_paddr_base failed!");

            0
        }
    };

    let spi_mem = unsafe { &*esp32h2::SPI0::ptr() };
    spi_mem
        .mmu_item_index()
        .write(|w| unsafe { w.spi_mmu_item_index().bits(entry_id) });

    let mmu_item_content = spi_mem
        .mmu_item_content()
        .read()
        .spi_mmu_item_content()
        .bits();

    (mmu_item_content & SOC_MMU_VALID_VAL_MASK) << shift_code
}

pub fn mmu_ll_check_entry_valid(_mmu_id: u32, entry_id: u32) -> bool {
    let spi_mem = unsafe { &*esp32h2::SPI0::ptr() };
    spi_mem
        .mmu_item_index()
        .write(|w| unsafe { w.spi_mmu_item_index().bits(entry_id) });

    let mmu_item_content = spi_mem
        .mmu_item_content()
        .read()
        .spi_mmu_item_content()
        .bits();

    (mmu_item_content & SOC_MMU_VALID) != 0
}
