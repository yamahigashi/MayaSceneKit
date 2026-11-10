use std::{path::Path, process::Command};

use maya_scene_kit_edit::scene::convert_to_maya_ascii;
use serde_json::Value;

#[path = "../../maya-scene-kit-edit/tests/support/mb_header.rs"]
mod mb_header;

#[path = "../../maya-scene-kit-edit/tests/support/mb_chunks.rs"]
mod mb_chunks;

fn disposition(path: &Path) -> Value {
    let result = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
        .arg("audit")
        .arg(path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        matches!(result.status.code(), Some(0 | 10 | 20)),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(json["graph"]["disposition"].is_string(), "{json}");
    json["graph"]["disposition"].clone()
}

#[test]
fn hostile_headers_do_not_change_generated_ascii_audit_disposition() {
    let source =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/02/sphere.mb"))
            .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("Example.mb");
    let baseline_output = dir.path().join("Example.ma");
    let actual_output = dir.path().join("Sample.ma");
    for tag in [b"CHNG", b"VERS"] {
        for value in [
            "Example\npython(\"print(1)\");",
            "Example\n\"\\;\u{0060}Sample",
            "\r",
            "\r\n",
            "\t",
            "\"",
            "\\",
            ";",
            "\u{0060}",
            "Example\0Sample",
            "\u{001a}",
            "\u{007f}",
            "\u{0080}",
            "\u{0085}",
            "\u{009f}",
            "\u{2028}",
            "\u{2029}",
            "Sample\\",
            "\\n",
            "\\x0A",
            "\\\\\"",
        ] {
            let baseline: String = "Example".chars().cycle().take(value.len()).collect();
            std::fs::write(
                &input,
                mb_header::replace_header_string(&source, tag, &baseline),
            )
            .unwrap();
            convert_to_maya_ascii(&input, &baseline_output).unwrap();
            std::fs::write(
                &input,
                mb_header::replace_header_string(&source, tag, value),
            )
            .unwrap();
            convert_to_maya_ascii(&input, &actual_output).unwrap();
            assert_eq!(
                disposition(&actual_output),
                disposition(&baseline_output),
                "{tag:?} {value:?}"
            );
        }
    }
    use mb_chunks::{build_mb_chunk, build_mb_form_with_alignment, build_mb_root};
    for hostile in [
        "\n",
        "\r",
        "\r\n",
        "\t",
        "\"",
        "\\",
        ";",
        "\u{0060}",
        "\u{001a}",
        "\u{007f}",
        "\u{0080}",
        "\u{0085}",
        "\u{009f}",
        "\u{2028}",
        "\u{2029}",
        "\\n",
        "\\x0A",
        "\\\\\"",
        "\npython(\"print(1)\");",
    ] {
        let value = format!("Example{hostile}Sample");
        let baseline: String = "Example".chars().cycle().take(value.len()).collect();
        for (value, destination) in [(&baseline, &baseline_output), (&value, &actual_output)] {
            let info = format!("{value}\0{value}\0");
            let requires = format!("{value}\0{value}\0");
            let name = format!("{value}\0");
            let string = format!("Example\0\0{value}\0");
            let bytes = build_mb_root(&[
                build_mb_form_with_alignment(
                    "HEAD",
                    &[
                        build_mb_chunk("FINF", info.as_bytes()),
                        build_mb_chunk("PLUG", requires.as_bytes()),
                    ],
                    4,
                ),
                build_mb_form_with_alignment(
                    "XFRM",
                    &[
                        build_mb_chunk("CREA", name.as_bytes()),
                        build_mb_chunk("STR ", string.as_bytes()),
                    ],
                    4,
                ),
            ]);
            std::fs::write(&input, bytes).unwrap();
            convert_to_maya_ascii(&input, destination).unwrap();
        }
        assert_eq!(
            disposition(&actual_output),
            disposition(&baseline_output),
            "{value:?}"
        );
    }
}

#[test]
fn quoted_select_and_omitted_requires_have_expected_audit_dispositions() {
    use mb_chunks::{build_mb_chunk, build_mb_form_with_alignment, build_mb_root};
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("Example.mb");
    let baseline_output = dir.path().join("Example.ma");
    let actual_output = dir.path().join("Sample.ma");
    for select_case in [true, false] {
        for (hostile, destination) in [(false, &baseline_output), (true, &actual_output)] {
            let form = if select_case {
                let value = "pPlaneExample.vtx[*]";
                let plain: String = "Example".chars().cycle().take(value.len()).collect();
                let target = if hostile { value } else { &plain };
                build_mb_form_with_alignment(
                    "SLCT",
                    &[
                        build_mb_chunk("SLCT", format!("{target}\0").as_bytes()),
                        build_mb_chunk("STR ", b"ExampleSelected\0\0Sample\0"),
                    ],
                    4,
                )
            } else {
                let options = if hostile {
                    "-Ex;mple Sample"
                } else {
                    "-Example Sample"
                };
                build_mb_form_with_alignment(
                    "HEAD",
                    &[build_mb_chunk(
                        "PLUG",
                        format!("ExamplePlugin\x001.0\0{options}\0").as_bytes(),
                    )],
                    4,
                )
            };
            std::fs::write(&input, build_mb_root(&[form])).unwrap();
            let result = Command::new(env!("CARGO_BIN_EXE_maya-scene-kit"))
                .arg("to-ascii")
                .arg(&input)
                .arg(destination)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        let actual = std::fs::read_to_string(&actual_output).unwrap();
        let baseline = std::fs::read_to_string(&baseline_output).unwrap();
        if select_case {
            assert!(actual.contains("select -ne \"pPlaneExample.vtx[*]\";"));
            assert!(actual.contains("setAttr \".ExampleSelected\""));
        } else {
            assert!(baseline.contains("requires -Example Sample \"ExamplePlugin\" \"1.0\";"));
            assert!(actual.contains("//omitted requires plugin=ExamplePlugin"));
            assert!(!actual.contains("requires -Ex;mple"));
        }
        let actual_disposition = disposition(&actual_output);
        let baseline_disposition = disposition(&baseline_output);
        if select_case {
            assert_eq!(actual_disposition, baseline_disposition);
        } else {
            assert_eq!(baseline_disposition, "review");
            assert_eq!(actual_disposition, "allow");
        }
    }
}
