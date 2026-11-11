pub(crate) fn attr_value_range(payload: &[u8]) -> Option<std::ops::Range<usize>> {
    let attr_end = payload.iter().position(|byte| *byte == 0)?;
    let start = attr_end.checked_add(2)?;
    let value = payload.get(start..)?;
    let end = start
        + value
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(value.len());
    Some(start..end)
}
