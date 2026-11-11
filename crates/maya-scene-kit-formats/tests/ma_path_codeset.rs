use maya_scene_kit_formats::ma::{
    rewrite::replace_raw_scene_paths_in_ma,
    types::{PathReplaceMode, PathReplaceRule},
};

fn replace(
    header: &str,
    replacement: &str,
) -> maya_scene_kit_formats::ma::rewrite::MaPathReplaceResult {
    let source = format!(
        "{header}createNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/Sample.png\";\n"
    );
    replace_raw_scene_paths_in_ma(
        source.as_bytes(),
        &[PathReplaceRule {
            from: "asset/example/Sample.png".into(),
            to: replacement.into(),
            mode: PathReplaceMode::Literal,
        }],
    )
    .unwrap()
}

#[test]
fn ascii_cp932_header_encodes_replacement_as_cp932() {
    let result = replace("//Codeset: 932\n", "asset/テクスチャ/Sample.png");
    let (expected, _, errors) = encoding_rs::SHIFT_JIS.encode("テクスチャ");
    assert!(!errors);
    assert_eq!(result.replacement_count, 1);
    assert!(
        result
            .bytes
            .windows(expected.len())
            .any(|w| w == expected.as_ref())
    );
    assert!(
        !result
            .bytes
            .windows("テクスチャ".len())
            .any(|w| w == "テクスチャ".as_bytes())
    );
}

#[test]
fn ascii_gbk_header_encodes_replacement_as_gbk() {
    let result = replace("//Codeset: 936\n", "asset/テクスチャ/Sample.png");
    let (expected, _, errors) = encoding_rs::GBK.encode("テクスチャ");
    assert!(!errors);
    assert_eq!(result.replacement_count, 1);
    assert!(
        result
            .bytes
            .windows(expected.len())
            .any(|w| w == expected.as_ref())
    );
    assert!(
        !result
            .bytes
            .windows("テクスチャ".len())
            .any(|w| w == "テクスチャ".as_bytes())
    );
}

#[test]
fn ascii_without_legacy_header_keeps_utf8_replacements() {
    for header in ["", "//Codeset: 65001\n"] {
        let result = replace(header, "asset/テクスチャ/Sample.png");
        assert_eq!(result.replacement_count, 1);
        assert_eq!(result.bytes, format!("{header}createNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset/テクスチャ/Sample.png\";\n").as_bytes());
    }
}

#[test]
fn ascii_cp932_header_skips_unrepresentable_replacement() {
    let result = replace("//Codeset: 932\n", "asset/example/😀.png");
    assert_eq!(result.skipped.unrepresentable, 1);
    assert_eq!(result.replacement_count, 0);
    assert_eq!(result.bytes, b"//Codeset: 932\ncreateNode file -n \"Example\";\nsetAttr \".ftn\" -type \"string\" \"asset/example/Sample.png\";\n");
}
