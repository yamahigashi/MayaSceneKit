pub fn replace_header_string(source: &[u8], tag: &[u8; 4], value: &str) -> Vec<u8> {
    assert_eq!(&source[..4], b"FOR8");
    assert_eq!(&source[36..40], b"HEAD");
    let head_size = u64::from_be_bytes(source[28..36].try_into().unwrap()) as usize;
    let mut cursor = 40;
    while cursor < 36 + head_size {
        let size = u64::from_be_bytes(source[cursor + 8..cursor + 16].try_into().unwrap()) as usize;
        let padded = size.div_ceil(8) * 8;
        if &source[cursor..cursor + 4] == tag {
            let mut payload = value.as_bytes().to_vec();
            payload.push(0);
            let new_size = payload.len();
            payload.resize(new_size.div_ceil(8) * 8, 0);
            let mut result = source.to_vec();
            result.splice(cursor + 16..cursor + 16 + padded, payload);
            result[cursor + 8..cursor + 16].copy_from_slice(&(new_size as u64).to_be_bytes());
            let new_head_size = head_size - padded + new_size.div_ceil(8) * 8;
            result[28..36].copy_from_slice(&(new_head_size as u64).to_be_bytes());
            let root_size = result.len() - 16;
            result[8..16].copy_from_slice(&(root_size as u64).to_be_bytes());
            return result;
        }
        cursor += 16 + padded;
    }
    panic!("header tag missing");
}
