use maya_mb::parse_bytes;

#[test]
fn accepts_omitted_terminal_child_padding() {
    let mut bytes = b"FOR8\0\0\0\0".to_vec();
    bytes.extend_from_slice(&26u64.to_be_bytes());
    bytes.extend_from_slice(b"MayaDATA\0\0\0\0");
    bytes.extend_from_slice(&6u64.to_be_bytes());
    bytes.extend_from_slice(b"Sample");
    let parsed = parse_bytes(bytes).unwrap();
    assert!(parsed.root().children_complete());
    assert_eq!(parsed.root().children().len(), 1);
    assert_eq!(parsed.payload(&parsed.root().children()[0]), b"Sample");
}
