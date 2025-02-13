#[inline(always)]
/// Helper funcion!
/// Change seq to partition number
pub fn seq_to_part(seq: u32, ota_count: usize) -> usize {
    ((seq as usize).saturating_sub(1)) % ota_count
}

#[inline(always)]
/// Helper funcion!
/// If crc of seq is correct it returns seq, otherwise default value is returned
#[allow(dead_code)]
pub fn seq_or_default(seq: &[u8], crc: u32, default: u32) -> u32 {
    let crc_calc = super::crc32::calc_crc32(seq, 0xFFFFFFFF);
    if crc == crc_calc {
        return u32::from_le_bytes(seq.try_into().expect("Wrong size?"));
    }

    default
}

#[inline(always)]
/// Helper function!
/// Check if crc is correct for given seq
pub fn is_crc_seq_correct(seq: u32, crc: u32) -> bool {
    let bytes = unsafe {
        let mut buf = [0; 4]; //u32
        core::ptr::copy_nonoverlapping(&seq as *const u32 as *const u8, buf.as_mut_ptr(), 4);

        buf
    };

    let crc_calc = super::crc32::calc_crc32(&bytes, 0xFFFFFFFF);
    crc == crc_calc
}
