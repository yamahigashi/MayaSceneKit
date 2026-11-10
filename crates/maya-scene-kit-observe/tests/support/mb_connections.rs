pub fn chunk(tag: &str, payload: &[u8], alignment: usize) -> Vec<u8> {
    assert_eq!(tag.len(), 4);
    assert_ne!(alignment, 0);
    let mut bytes = tag.as_bytes().to_vec();
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(alignment), 0);
    bytes
}

pub fn form(tag: &str, children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = tag.as_bytes().to_vec();
    payload.extend(children.concat());
    chunk("FOR8", &payload, 4)
}

pub fn scene(children: &[Vec<u8>]) -> Vec<u8> {
    form("Maya", children)
}

pub fn attr(tag: &str, name: &str, value: &[u8]) -> Vec<u8> {
    let mut payload = format!("{name}\0\0").into_bytes();
    payload.extend(value);
    chunk(tag, &payload, 8)
}

pub fn node(form_name: &str, name: &str, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut children = vec![chunk("CREA", format!("{name}\0").as_bytes(), 8)];
    children.extend_from_slice(attrs);
    form(form_name, &children)
}

pub fn script(attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut values = vec![
        attr("DBLE", "st", &1.0f64.to_be_bytes()),
        attr("DBLE", "stp", &1.0f64.to_be_bytes()),
    ];
    values.extend_from_slice(attrs);
    node("SCRP", "ExampleScript", &values)
}

pub fn connection(source: &str, destination: &str) -> Vec<u8> {
    chunk("CWFL", format!("\0{source}\0{destination}\0").as_bytes(), 8)
}

pub fn example(values: &[&[u8]], source: &str, destination: &str, extra: &[Vec<u8>]) -> Vec<u8> {
    let attrs: Vec<_> = values.iter().map(|v| attr("STR ", "note", v)).collect();
    let mut forms = vec![
        node("XFRM", "ExampleSource", &attrs),
        script(&[]),
        form("CONS", &[connection(source, destination)]),
    ];
    forms.extend_from_slice(extra);
    scene(&forms)
}
