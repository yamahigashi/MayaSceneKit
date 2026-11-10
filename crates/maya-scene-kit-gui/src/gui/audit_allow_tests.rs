use std::{cell::RefCell, prelude::v1::test, rc::Rc};

use maya_scene_kit_audit::scene::{AuditDisposition, AuditFindingCode};
use maya_scene_kit_observe::scene::evidence::{ExecutionLanguage, ExecutionTrigger};
use tempfile::tempdir;

use super::*;
use crate::persistence::{UserAllowlistDocument, read_user_allowlist};

const SCENE: &str = concat!(
    "//Maya ASCII 2026 scene\n",
    "requires maya \"2026\";\n",
    "createNode script -n \"ExampleScriptNode\";\n",
    "\tsetAttr \".b\" -type \"string\" \"exec \\\"Example\\\"\";\n",
    "\tsetAttr \".st\" 1;\n",
);
const HASH: &str = "sha256:79a04cad1f2f3e49d4efcda479915fdc244cd65b27a931f7bed1cfff42ff7e20";
const PARENT_BODY: &str = "python(\"exec('print(1)')\")";

fn scene(body: &str) -> String {
    let body = body
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    format!(
        "//Maya ASCII 2026 scene\nrequires maya \"2026\";\ncreateNode script -n \"ExampleScriptNode\";\n\tsetAttr \".b\" -type \"string\" \"{body}\";\n\tsetAttr \".st\" 1;\n"
    )
}

fn current_row(path: &Path, plan: &ScriptAuditPlan) -> SceneRow {
    let RowJobResult::Analyze(result) = analyze_row_with_options(
        path,
        AuditModePreference::StrictDefault,
        &LoadOptions::default(),
        plan,
    )
    .unwrap() else {
        panic!("expected analysis");
    };
    let mut row = SceneRow::from_path(1, path.to_path_buf()).unwrap();
    row.set_audit_report(Some(result.audit_report), result.audit_file_state);
    row.audit_plan_fingerprint = Some(result.audit_plan_fingerprint);
    row.paths_report = result.paths_report;
    row.dump_report = result.dump_report;
    row.analyzed_audit_mode = Some(result.audit_mode);
    row.status = FileStatus::Audited;
    row.selected = true;
    row.sync_findings_count();
    row
}

fn target(report: &AuditReport, code: AuditFindingCode) -> AuditDetailCodeTarget {
    let surface = report.surface_for(
        report
            .findings
            .iter()
            .find(|finding| finding.code == code)
            .unwrap(),
    );
    AuditDetailCodeTarget {
        origin: surface.origin.clone(),
        derived: surface.derivation != AuditSurfaceDerivation::Observed,
    }
}

fn load(row: &SceneRow, code: AuditFindingCode) -> AuditDetailCodeResult {
    let report = row.display_audit_report().unwrap();
    load_audit_surface_text_for_file_state(
        &row.path,
        &LoadOptions::default(),
        &target(report, code),
        row.audit_file_state,
        &OfferInput::from(report),
    )
}

fn material(result: &AuditDetailCodeResult) -> &AuditAllowMaterial {
    let AuditDetailCodeState::Loaded { allow, .. } = &result.state else {
        panic!("expected loaded: {:?}", result.state);
    };
    allow
}

fn request(
    row: &SceneRow,
    code: AuditFindingCode,
    user_path: &Path,
    plan: &ScriptAuditPlan,
    allowlist: AuditAllowlist,
) -> AllowAddRequest {
    let result = load(row, code);
    let allow = material(&result);
    AllowAddRequest {
        scene_path: row.path.clone(),
        user_path: user_path.to_path_buf(),
        file_state: row.audit_file_state,
        options: LoadOptions::default(),
        audit_mode: AuditModePreference::StrictDefault,
        plan: Arc::new(plan.clone()),
        allowlist,
        target: target(row.display_audit_report().unwrap(), code),
        target_code: code.as_str().to_string(),
        entry: build_user_allowlist_entry(
            allow.hash,
            AllowlistEntryDraft {
                node: allow.root_origin.node_name.as_deref(),
                attr: allow.root_origin.attr_name.as_deref(),
                body: result.text.as_deref().unwrap(),
                reason: "Example reason",
                codes: &BTreeSet::from([code.as_str().to_string()]),
            },
            SystemTime::UNIX_EPOCH + Duration::from_secs(1794043800),
            Some("Example".into()),
        ),
    }
}

fn open_shell<'a>(
    cx: &'a mut TestAppContext,
    dir: &Path,
    user_path: &Path,
) -> (Entity<GuiShell>, &'a mut VisualTestContext) {
    cx.update(init_gui_app);
    let slot = Rc::new(RefCell::new(None));
    let built = slot.clone();
    let (_, visual_cx) = cx.add_window_view(|window, cx| {
        let menu_bar = TopMenuBar::new(window, cx);
        let shell = cx.new(|cx| {
            GuiShell::new_with_state_and_cache_root(
                menu_bar,
                window,
                cx,
                PersistedState {
                    locale: crate::model::LocalePreference::English,
                    analysis_cache_enabled: false,
                    ..PersistedState::default()
                },
                dir.join("ExampleCache"),
                None,
                Some(dir.join("ExampleApp/allowlist.json")),
                Some(user_path.to_path_buf()),
            )
        });
        built.replace(Some(shell.clone()));
        Root::new(shell, window, cx)
    });
    let shell = slot.borrow().clone().unwrap();
    (shell, visual_cx)
}

fn open_finding(
    shell: &mut GuiShell,
    row: SceneRow,
    code: AuditFindingCode,
    window: &mut Window,
    cx: &mut Context<GuiShell>,
) -> AuditResultRowKey {
    let index = row
        .display_audit_report()
        .unwrap()
        .findings
        .iter()
        .position(|finding| finding.code == code)
        .unwrap();
    shell.replace_rows(vec![row]);
    shell.refresh_file_table(cx);
    shell.refresh_audit_table(cx);
    let key = shell
        .audit_rows
        .iter()
        .flat_map(|row| &row.row_keys)
        .find(|key| key.item_kind == AuditResultItemKind::Finding && key.item_index == index)
        .unwrap()
        .clone();
    shell.open_audit_detail_dialog(key.clone(), window, cx);
    key
}

#[test]
fn audit_allow_loaded_hash_uses_observed_root() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    fs::write(&path, SCENE).unwrap();
    let plan = gui_audit_plan(AuditAllowlist::default()).unwrap();
    let row = current_row(&path, &plan);
    let result = load(&row, AuditFindingCode::MelExec);
    let allow = material(&result);
    assert_eq!(allow.hash.to_string(), HASH);
    assert_eq!(
        allow.root_origin,
        target(
            row.display_audit_report().unwrap(),
            AuditFindingCode::MelExec
        )
        .origin
    );
    assert_eq!(allow.root_origin.lang, ExecutionLanguage::Mel);
    assert_eq!(allow.root_origin.trigger, ExecutionTrigger::FileOpen);
    assert_eq!(allow.root_origin.attr_name.as_deref(), Some(".b"));
    assert_eq!(
        allow.root_origin.node_name.as_deref(),
        Some("ExampleScriptNode")
    );
    assert_eq!(
        allow.root_origin.source_kind.as_deref(),
        Some("scriptType=1")
    );
    assert_eq!(result.text.as_deref(), Some("exec \"Example\""));
    fs::write(&path, scene(PARENT_BODY)).unwrap();
    let row = current_row(&path, &plan);
    let result = load(&row, AuditFindingCode::PythonExec);
    let allow = material(&result);
    let report = row.display_audit_report().unwrap();
    let parent = target(report, AuditFindingCode::MelPython);
    let derived = target(report, AuditFindingCode::PythonExec);
    assert_eq!(allow.root_origin, parent.origin);
    assert_eq!(
        allow.hash,
        allowlist_surface_hash(&parent.origin, PARENT_BODY)
    );
    assert_ne!(
        allow.hash,
        allowlist_surface_hash(&derived.origin, "exec('print(1)')")
    );
    assert_eq!(result.text.as_deref(), Some(PARENT_BODY));
}

#[gpui::test]
fn audit_allow_offered_codes_follow_resolved_findings(cx: &mut TestAppContext) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    fs::write(&path, scene(PARENT_BODY)).unwrap();
    let plan = gui_audit_plan(AuditAllowlist::default()).unwrap();
    let row = current_row(&path, &plan);
    let mut report = row.display_audit_report().unwrap().clone();
    let target = target(&report, AuditFindingCode::PythonExec);
    let observation = Loader::new(LoadOptions::default())
        .observe_analysis_path(&path)
        .unwrap();
    let catalog = observation
        .observed_execution_catalog_with_digests(0, false)
        .unwrap();
    let mut surfaces: Vec<_> = catalog
        .surfaces
        .into_iter()
        .map(|entry| entry.surface)
        .collect();
    let codes = |report: &AuditReport, surfaces: &[ExecutionSurface]| {
        material(&audit_surface_code_result(
            &target,
            surfaces,
            &OfferInput::from(report),
        ))
        .offered_codes
        .clone()
    };
    assert_eq!(codes(&report, &surfaces), ["mel_python", "python_pyexec"]);
    let mel = report
        .findings
        .iter()
        .find(|finding| finding.code == AuditFindingCode::MelPython)
        .unwrap()
        .clone();
    report.findings.push(mel.clone());
    assert_eq!(codes(&report, &surfaces), ["mel_python", "python_pyexec"]);
    report
        .findings
        .iter_mut()
        .find(|finding| finding.code == AuditFindingCode::MelPython)
        .unwrap()
        .allowed_by = Some(AuditAllowRef {
        hash: material(&load(&row, AuditFindingCode::PythonExec)).hash,
        source: AllowlistSource::User,
    });
    assert_eq!(codes(&report, &surfaces), ["python_pyexec"]);
    let mut poisoned = mel.clone();
    poisoned.code = AuditFindingCode::PythonParseFailure;
    report.findings.push(poisoned);
    let mut custom = mel.clone();
    custom.code = AuditFindingCode::CustomRuleMatch;
    report.findings.push(custom);
    let mut other_surface = report.surfaces[mel.surface_index].clone();
    other_surface.origin.node_name = Some("SampleScriptNode".into());
    let mut other = mel;
    other.code = AuditFindingCode::MelExec;
    other.surface_index = report.surfaces.len();
    surfaces.push(ExecutionSurface {
        origin: other_surface.origin.clone(),
        text: PARENT_BODY.into(),
        preview: String::new(),
    });
    assert_eq!(
        allowlist_surface_hash(&surfaces[0].origin, &surfaces[0].text),
        allowlist_surface_hash(&surfaces.last().unwrap().origin, PARENT_BODY)
    );
    report.surfaces.push(other_surface);
    report.findings.push(other);
    assert_eq!(codes(&report, &surfaces), ["python_pyexec"]);
    let (shell, visual_cx) = open_shell(
        cx,
        dir.path(),
        &dir.path().join("ExampleUser/allowlist.json"),
    );
    shell.update_in(visual_cx, |shell, window, cx| {
        open_finding(shell, row, AuditFindingCode::PythonExec, window, cx);
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.open_audit_allow_form(window, cx);
        assert_eq!(
            shell
                .audit_detail_dialog
                .as_ref()
                .unwrap()
                .allow_form
                .as_ref()
                .unwrap()
                .checked_codes,
            BTreeSet::from(["python_pyexec".into()])
        );
    });
}

#[test]
fn audit_allow_verification_rejects_poisoned_body() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let user = dir.path().join("ExampleUser/allowlist.json");
    let plan = gui_audit_plan(AuditAllowlist::default()).unwrap();
    fs::write(
        &path,
        scene("python(\"if example syntax:\\n    value = data.decode(\");"),
    )
    .unwrap();
    let row = current_row(&path, &plan);
    let report = row.display_audit_report().unwrap();
    for code in [
        AuditFindingCode::MelPython,
        AuditFindingCode::PythonParseFailure,
    ] {
        assert!(report.findings.iter().any(|finding| finding.code == code));
    }
    let candidate = request(
        &row,
        AuditFindingCode::MelPython,
        &user,
        &plan,
        AuditAllowlist::default(),
    );
    let bytes = serde_json::json!({"version":1,"entries":[candidate.entry]}).to_string();
    fs::create_dir_all(user.parent().unwrap()).unwrap();
    fs::write(&user, &bytes).unwrap();
    let allowlist = AuditAllowlist::from_json(&bytes, AllowlistSource::User).unwrap();
    let plan_with_entry = plan.clone().with_allowlist(allowlist.clone());
    let row = current_row(&path, &plan_with_entry);
    assert!(
        row.display_audit_report()
            .unwrap()
            .findings
            .iter()
            .all(|finding| finding.allowed_by.is_none())
    );
    assert!(
        material(&load(&row, AuditFindingCode::MelPython))
            .offered_codes
            .contains(&"mel_python".to_string())
    );
    assert_eq!(
        verify_and_add_user_allowlist(request(
            &row,
            AuditFindingCode::MelPython,
            &user,
            &plan_with_entry,
            allowlist.clone()
        )),
        Err(AllowAddError::VerificationRefused)
    );
    assert_eq!(fs::read(&user).unwrap(), bytes.as_bytes());
    let missing = dir.path().join("SampleUser/allowlist.json");
    assert_eq!(
        verify_and_add_user_allowlist(request(
            &row,
            AuditFindingCode::MelPython,
            &missing,
            &plan_with_entry,
            allowlist
        )),
        Err(AllowAddError::VerificationRefused)
    );
    assert!(!missing.exists());
    fs::write(&path, SCENE).unwrap();
    let row = current_row(&path, &plan);
    let mut missing_own_code = request(
        &row,
        AuditFindingCode::MelExec,
        &user,
        &plan,
        AuditAllowlist::default(),
    );
    missing_own_code.entry.codes = vec!["mel_python".into()];
    assert_eq!(
        verify_and_add_user_allowlist(missing_own_code),
        Err(AllowAddError::VerificationRefused)
    );
    assert_eq!(fs::read(&user).unwrap(), bytes.as_bytes());
    let candidate = request(
        &row,
        AuditFindingCode::MelExec,
        &missing,
        &plan,
        AuditAllowlist::default(),
    );
    assert_eq!(verify_audit_allowance(&candidate), Ok(()));
    let merged = AuditAllowlist::from_json(
        &serde_json::json!({"version":1,"entries":[candidate.entry]}).to_string(),
        AllowlistSource::User,
    )
    .unwrap();
    let allowed = current_row(&path, &plan.clone().with_allowlist(merged));
    assert_eq!(
        allowed.display_audit_report().unwrap().findings[0].allowed_by,
        Some(AuditAllowRef {
            hash: HASH.parse().unwrap(),
            source: AllowlistSource::User
        })
    );
    fs::write(&path, format!("{SCENE}\n")).unwrap();
    assert_eq!(
        verify_and_add_user_allowlist(candidate),
        Err(AllowAddError::FileChanged)
    );
    assert!(!missing.exists());
    assert_eq!(fs::read(&user).unwrap(), bytes.as_bytes());
    assert_eq!(
        render_allow_add_error(
            &AllowAddError::FileChanged,
            &I18n::new(SupportedLocale::English)
        ),
        "The file changed after analysis. No entry was written; re-audit the file."
    );
}

#[gpui::test]
fn audit_allow_enablement_and_catalog_texts(cx: &mut TestAppContext) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let user = dir.path().join("ExampleUser/allowlist.json");
    fs::write(&path, SCENE).unwrap();
    let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
    shell.update_in(visual_cx, |shell, window, cx| {
        let row = current_row(&path, &shell.audit_plan);
        open_finding(shell, row, AuditFindingCode::MelExec, window, cx);
    });
    visual_cx.run_until_parked();
    assert!(visual_cx.debug_bounds("audit-detail-allow").is_some());
    shell.update_in(visual_cx, |shell, window, cx| {
        assert_eq!(shell.audit_detail_allow_disabled_reason(), None);
        let loaded = shell.audit_detail_dialog.as_ref().unwrap().code.clone();
        let key = shell.audit_detail_dialog.as_ref().unwrap().key.clone();
        let row_index = shell
            .audit_rows
            .iter()
            .position(|row| row.row_keys.contains(&key))
            .unwrap();
        let mut other_key = key.clone();
        other_key.row_id = 2;
        shell.audit_rows[row_index].row_keys.push(other_key);
        assert_eq!(
            shell.audit_detail_allow_disabled_reason(),
            Some("audit_allow.grouped")
        );
        shell.audit_rows[row_index].row_keys.pop();
        for code in [
            AuditDetailCodeState::Loading { request: 0 },
            AuditDetailCodeState::NotApplicable,
            AuditDetailCodeState::NotFound,
            AuditDetailCodeState::Ambiguous,
            AuditDetailCodeState::Failed {
                error: "Example error".into(),
            },
            AuditDetailCodeState::Unavailable,
            AuditDetailCodeState::FileChanged,
            AuditDetailCodeState::TooLarge,
        ] {
            shell.audit_detail_dialog.as_mut().unwrap().code = code;
            assert_eq!(
                shell.audit_detail_allow_disabled_reason(),
                Some("audit_allow.code_required")
            );
        }
        shell.audit_detail_dialog.as_mut().unwrap().code = loaded;
        shell.rows[0].audit_report.as_mut().unwrap().findings[key.item_index].allowed_by =
            Some(AuditAllowRef {
                hash: HASH.parse().unwrap(),
                source: AllowlistSource::User,
            });
        assert_eq!(
            shell.audit_detail_allow_disabled_reason(),
            Some("audit_allow.already_allowed")
        );
        shell.rows[0].audit_report.as_mut().unwrap().findings[key.item_index].allowed_by = None;
        for code in [
            AuditFindingCode::UnknownExecutionLanguage,
            AuditFindingCode::UnknownExecutionTrigger,
            AuditFindingCode::PythonParseFailure,
            AuditFindingCode::PythonUnresolvedCallTarget,
            AuditFindingCode::MelParseDiagnostics,
            AuditFindingCode::MelCallbackFlag,
            AuditFindingCode::CustomRuleMatch,
        ] {
            shell.rows[0].audit_report.as_mut().unwrap().findings[key.item_index].code = code;
            assert_eq!(
                shell.audit_detail_allow_disabled_reason(),
                Some("audit_allow.never_allowed")
            );
        }
        shell.rows[0].audit_report.as_mut().unwrap().findings[key.item_index].code =
            AuditFindingCode::MelExec;
        shell.rows[0].busy = Some(RowOperation::Analyze);
        assert_eq!(
            shell.audit_detail_allow_disabled_reason(),
            Some("audit_allow.busy")
        );
        shell.rows[0].busy = None;
        shell.rows[0].status = FileStatus::Audited;
        shell.rows[0]
            .path_overrides
            .insert(0, "asset/example/file.fbx".into());
        assert_eq!(
            shell.audit_detail_allow_disabled_reason(),
            Some("audit_allow.dirty")
        );
        shell.rows[0].path_overrides.clear();
        shell.rows[0].analyzed_audit_mode = None;
        assert_eq!(
            shell.audit_detail_allow_disabled_reason(),
            Some("audit_allow.stale")
        );
        shell.rows[0].analyzed_audit_mode = Some(shell.state.audit_mode);
        shell.user_allowlist_path = None;
        assert_eq!(
            shell.audit_detail_allow_disabled_reason(),
            Some("audit_allow.no_user_path")
        );
        shell.user_allowlist_path = Some(user.clone());
        shell.open_audit_allow_form(window, cx);
        let form = shell
            .audit_detail_dialog
            .as_ref()
            .unwrap()
            .allow_form
            .as_ref()
            .unwrap();
        assert_eq!(form.checked_codes, BTreeSet::from(["mel_exec".into()]));
        assert!(
            form.reason_input
                .read(cx)
                .focus_handle(cx)
                .is_focused(window)
        );
        assert!(!shell.audit_allow_add_disabled());
        shell
            .audit_detail_dialog
            .as_mut()
            .unwrap()
            .allow_form
            .as_mut()
            .unwrap()
            .request = Some(1);
        assert!(shell.audit_allow_add_disabled());
        assert_eq!(shell.i18n().text("audit_allow.adding"), "Adding…");
        shell
            .audit_detail_dialog
            .as_mut()
            .unwrap()
            .allow_form
            .as_mut()
            .unwrap()
            .request = None;
        shell.audit_allow_in_flight = true;
        assert!(shell.audit_allow_add_disabled());
        shell.audit_allow_in_flight = false;
    });
    let own = visual_cx.debug_bounds("audit-allow-own-code").unwrap();
    visual_cx.simulate_click(own.center(), Modifiers::default());
    shell.update_in(visual_cx, |shell, _, _| {
        assert!(
            shell
                .audit_detail_dialog
                .as_ref()
                .unwrap()
                .allow_form
                .as_ref()
                .unwrap()
                .checked_codes
                .contains("mel_exec")
        );
    });
    let (other, other_cx) = open_shell(visual_cx, dir.path(), &user);
    other.update_in(other_cx, |shell, window, cx| {
        shell.replace_rows(vec![current_row(&path, &shell.audit_plan)]);
        shell.refresh_file_table(cx);
        shell.refresh_audit_table(cx);
        shell.open_audit_detail_dialog(
            AuditResultRowKey {
                row_id: 1,
                item_kind: AuditResultItemKind::DumpScriptNode,
                item_index: 0,
            },
            window,
            cx,
        );
        assert_eq!(
            shell.audit_detail_allow_disabled_reason(),
            Some("audit_allow.unavailable")
        );
    });
    assert!(other_cx.debug_bounds("audit-detail-allow").is_none());
    let catalogs: [BTreeMap<String, String>; 3] = [
        serde_json::from_str(include_str!("../../locales/en.json")).unwrap(),
        serde_json::from_str(include_str!("../../locales/ja.json")).unwrap(),
        serde_json::from_str(include_str!("../../locales/cn.json")).unwrap(),
    ];
    for (key, expected) in ALLOW_TEXTS {
        for (catalog, expected) in catalogs.iter().zip(expected) {
            assert_eq!(
                catalog.get(*key).map(String::as_str),
                Some(*expected),
                "{key}"
            );
        }
    }
}

const ALLOW_TEXTS: &[(&str, [&str; 3])] = &[
    (
        "action.allow_threat",
        ["Allow this threat…", "この脅威を許可…", "允许此威胁…"],
    ),
    (
        "audit_allow.unavailable",
        [
            "This finding is unavailable.",
            "この検出は利用できません。",
            "此检测项不可用。",
        ],
    ),
    (
        "audit_allow.grouped",
        [
            "Open a single finding to allow it.",
            "許可するには単独の検出を開いてください。",
            "请打开单个检测项以允许它。",
        ],
    ),
    (
        "audit_allow.code_required",
        [
            "Load the full script text before allowing it.",
            "許可するにはスクリプト全文の読み込みが必要です。",
            "允许前需加载完整脚本文本。",
        ],
    ),
    (
        "audit_allow.already_allowed",
        [
            "This finding is already allowed.",
            "この検出は許可済みです。",
            "此检测项已被允许。",
        ],
    ),
    (
        "audit_allow.never_allowed",
        [
            "This finding cannot be allowed.",
            "この検出は許可できません。",
            "无法允许此检测项。",
        ],
    ),
    (
        "audit_allow.dirty",
        [
            "Save staged edits before allowing this finding.",
            "この検出を許可する前に未保存の編集を保存してください。",
            "允许此检测项前请保存暂存的编辑。",
        ],
    ),
    (
        "audit_allow.stale",
        [
            "Re-audit this file before allowing this finding.",
            "この検出を許可する前にファイルを再監査してください。",
            "允许此检测项前请重新审核文件。",
        ],
    ),
    (
        "audit_allow.no_user_path",
        [
            "The user allowlist path is unavailable.",
            "ユーザー許可リストの保存先がありません。",
            "用户允许列表路径不可用。",
        ],
    ),
    (
        "audit_allow.codes",
        ["Findings to allow", "許可する検出", "要允许的检测项"],
    ),
    (
        "audit_allow.reason",
        ["Reason (optional)", "理由（任意）", "原因（可选）"],
    ),
    (
        "audit_allow.warning",
        [
            "Allowing trusts this exact script text. If it reads data at run time (for example eval of an attribute), that data is trusted too.",
            "許可すると、このスクリプト本文を信頼します。実行時にデータを読み取る場合（属性値の eval など）、そのデータも信頼します。",
            "允许即表示信任这段完全相同的脚本文本。如果它在运行时读取数据（例如对属性值执行 eval），也会信任这些数据。",
        ],
    ),
    ("audit_allow.adding", ["Adding…", "追加中…", "正在添加…"]),
    (
        "audit_allow.verification_refused",
        [
            "Re-audit could not allow this finding. No entry was written.",
            "再監査でこの検出を許可できませんでした。許可リストには書き込んでいません。",
            "重新审核未能允许此检测项，未写入任何条目。",
        ],
    ),
    (
        "audit_allow.audit_failed",
        [
            "Could not verify this finding: {error}",
            "この検出を検証できませんでした: {error}",
            "无法验证此检测项：{error}",
        ],
    ),
    (
        "banner.allowlist_added",
        [
            "Added to the allowlist: {count} code(s)",
            "許可リストに追加しました: {count} 件の検出コード",
            "已添加到允许列表：{count} 个检测代码",
        ],
    ),
    (
        "banner.allowlist_write_failed",
        [
            "Could not write allowlist {path}: {error}",
            "許可リストに書き込めませんでした: {path}: {error}",
            "无法写入允许列表 {path}: {error}",
        ],
    ),
    (
        "banner.allowlist_already_present",
        [
            "The selected codes are already in the allowlist",
            "選択した検出コードは既に許可リストにあります",
            "所选检测代码已在允许列表中",
        ],
    ),
    (
        "audit_allow.file_changed",
        [
            "The file changed after analysis. No entry was written; re-audit the file.",
            "解析後にファイルが変更されました。許可リストには書き込んでいません。再監査してください。",
            "分析后文件已更改，未写入任何条目，请重新审核。",
        ],
    ),
    (
        "audit_allow.busy",
        [
            "This file is being processed.",
            "このファイルは処理中です。",
            "此文件正在处理中。",
        ],
    ),
];

#[gpui::test]
fn audit_allow_add_flow_reloads_and_reaudits(cx: &mut TestAppContext) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let user = dir.path().join("ExampleUser/allowlist.json");
    fs::write(&path, SCENE).unwrap();
    fs::create_dir_all(user.parent().unwrap()).unwrap();
    fs::write(&user, "{\"version\":1,\"entries\":[]}").unwrap();
    let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
    let old_fingerprint = shell.update_in(visual_cx, |shell, window, cx| {
        assert!(!shell.workspace_scan_active());
        open_finding(
            shell,
            current_row(&path, &shell.audit_plan),
            AuditFindingCode::MelExec,
            window,
            cx,
        );
        shell.audit_plan_fingerprint.clone()
    });
    visual_cx.run_until_parked();
    let observed = Rc::new(RefCell::new(false));
    shell.update_in(visual_cx, |shell, window, cx| {
        assert!(matches!(
            shell.audit_detail_dialog.as_ref().unwrap().code,
            AuditDetailCodeState::Loaded { .. }
        ));
        let observed = observed.clone();
        let user = user.clone();
        cx.observe_self(move |shell, _| {
            if let Some(message @ BannerMessage::AllowlistAdded { count: 1 }) =
                &shell.status_message
            {
                assert_eq!(
                    render_banner_message(&shell.i18n(), message),
                    "Added to the allowlist: 1 code(s)"
                );
                assert!(
                    shell
                        .audit_detail_dialog
                        .as_ref()
                        .is_none_or(|state| state.allow_form.is_none())
                );
                assert_ne!(shell.audit_plan_fingerprint, old_fingerprint);
                assert_eq!(
                    read_user_allowlist(&user).unwrap().entries[0]
                        .reason
                        .as_deref(),
                    Some("Example reason")
                );
                *observed.borrow_mut() = true;
            }
        })
        .detach();
        shell.open_audit_allow_form(window, cx);
        shell
            .audit_detail_dialog
            .as_ref()
            .unwrap()
            .allow_form
            .as_ref()
            .unwrap()
            .reason_input
            .update(cx, |input, cx| {
                input.set_value("Example reason", window, cx)
            });
        shell.submit_audit_allow_form(window, cx);
        assert!(shell.audit_allow_in_flight);
        assert!(shell.audit_allow_add_disabled());
    });
    visual_cx.run_until_parked();
    assert!(
        *observed.borrow(),
        "write-result banner must precede the analysis banner"
    );
    // The normal selected-row scheduler uses a debounce timer.
    visual_cx.executor().advance_clock(AUTO_ANALYZE_DEBOUNCE);
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, _, _| {
        assert!(!shell.audit_allow_in_flight);
        let row = &shell.rows[0];
        assert!(row.analysis_current_for(shell.state.audit_mode));
        let report = row.display_audit_report().unwrap();
        assert_eq!(report.finding_count(), 1);
        assert_eq!(report.allowed_finding_count(), 1);
        assert_eq!(
            report.findings[0].allowed_by,
            Some(AuditAllowRef {
                hash: HASH.parse().unwrap(),
                source: AllowlistSource::User
            })
        );
        assert_eq!(row.effective_findings_count(), 0);
        assert_eq!(report.disposition, AuditDisposition::Review);
    });
    for (locale, expected) in [
        (
            SupportedLocale::Japanese,
            "許可リストに追加しました: 1 件の検出コード",
        ),
        (SupportedLocale::Chinese, "已添加到允许列表：1 个检测代码"),
    ] {
        assert_eq!(
            render_banner_message(
                &I18n::new(locale),
                &BannerMessage::AllowlistAdded { count: 1 }
            ),
            expected
        );
    }
    assert!(!dir.path().join("ExampleApp/allowlist.json").exists());
}

#[gpui::test]
fn audit_allow_write_failure_keeps_form(cx: &mut TestAppContext) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let user = dir.path().join("ExampleUser/allowlist.json");
    fs::write(&path, SCENE).unwrap();
    fs::create_dir_all(&user).unwrap();
    let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
    shell.update_in(visual_cx, |shell, window, cx| {
        open_finding(
            shell,
            current_row(&path, &shell.audit_plan),
            AuditFindingCode::MelExec,
            window,
            cx,
        );
    });
    visual_cx.run_until_parked();
    let (reason_input, fingerprint) = shell.update_in(visual_cx, |shell, window, cx| {
        shell.open_audit_allow_form(window, cx);
        let input = shell
            .audit_detail_dialog
            .as_ref()
            .unwrap()
            .allow_form
            .as_ref()
            .unwrap()
            .reason_input
            .clone();
        input.update(cx, |input, cx| {
            input.set_value("Example reason", window, cx)
        });
        shell.submit_audit_allow_form(window, cx);
        (input, shell.audit_plan_fingerprint.clone())
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, _, cx| {
        let form = shell
            .audit_detail_dialog
            .as_ref()
            .unwrap()
            .allow_form
            .as_ref()
            .unwrap();
        assert_eq!(form.request, None);
        assert_eq!(form.reason_input, reason_input);
        assert_eq!(
            form.reason_input.read(cx).value().as_ref(),
            "Example reason"
        );
        assert_eq!(form.checked_codes, BTreeSet::from(["mel_exec".into()]));
        let Some(AllowAddError::WriteFailed { path, error }) = &form.error else {
            panic!("expected write failure");
        };
        assert_eq!(path, &user);
        let Some(
            message @ BannerMessage::AllowlistWriteFailed {
                path: banner_path,
                error: banner_error,
            },
        ) = &shell.status_message
        else {
            panic!("expected write banner");
        };
        assert_eq!(banner_path, path);
        assert_eq!(banner_error, error);
        assert_eq!(
            render_banner_message(&shell.i18n(), message),
            format!("Could not write allowlist {}: {error}", user.display())
        );
        assert_eq!(shell.audit_plan_fingerprint, fingerprint);
        assert!(!shell.audit_allow_in_flight);
    });
    assert!(fs::read_dir(&user).unwrap().next().is_none());
    for (locale, expected) in [
        (
            SupportedLocale::English,
            "Could not write allowlist ExampleUser/allowlist.json: Example error",
        ),
        (
            SupportedLocale::Japanese,
            "許可リストに書き込めませんでした: ExampleUser/allowlist.json: Example error",
        ),
        (
            SupportedLocale::Chinese,
            "无法写入允许列表 ExampleUser/allowlist.json: Example error",
        ),
    ] {
        assert_eq!(
            render_banner_message(
                &I18n::new(locale),
                &BannerMessage::AllowlistWriteFailed {
                    path: "ExampleUser/allowlist.json".into(),
                    error: "Example error".into()
                }
            ),
            expected
        );
    }
}

#[gpui::test]
fn audit_allow_already_present_and_duplicate_hash(cx: &mut TestAppContext) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let user = dir.path().join("ExampleUser/allowlist.json");
    fs::write(&path, SCENE).unwrap();
    let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
    let (key, entry) = shell.update_in(visual_cx, |shell, window, cx| {
        let row = current_row(&path, &shell.audit_plan);
        let entry = request(
            &row,
            AuditFindingCode::MelExec,
            &user,
            &shell.audit_plan,
            AuditAllowlist::default(),
        )
        .entry;
        (
            open_finding(shell, row, AuditFindingCode::MelExec, window, cx),
            entry,
        )
    });
    visual_cx.run_until_parked();
    assert_eq!(add_user_allowlist_entry(&user, &entry).unwrap(), 1);
    let bytes = fs::read(&user).unwrap();
    let count = add_user_allowlist_entry(&user, &entry).unwrap();
    assert_eq!(count, 0);
    assert_eq!(fs::read(&user).unwrap(), bytes);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.apply_audit_allow_result(&key, 1, Ok(count), window, cx);
        assert!(matches!(
            shell.status_message,
            Some(BannerMessage::AllowlistAlreadyPresent)
        ));
        assert_eq!(
            render_banner_message(&shell.i18n(), shell.status_message.as_ref().unwrap()),
            "The selected codes are already in the allowlist"
        );
    });
    let mut first = entry.clone();
    first.label = None;
    first.preview = None;
    first.reason = None;
    let mut second = entry.clone();
    second.codes = vec!["mel_eval".into()];
    second.label = Some("Sample".into());
    let document = UserAllowlistDocument {
        version: 1,
        entries: vec![first, second.clone()],
    };
    let bytes = serde_json::to_vec(&document).unwrap();
    fs::write(&user, &bytes).unwrap();
    assert_eq!(add_user_allowlist_entry(&user, &entry).unwrap(), 0);
    assert_ne!(fs::read(&user).unwrap(), bytes);
    let filled = read_user_allowlist(&user).unwrap();
    assert_eq!(filled.entries[0], entry);
    assert_eq!(filled.entries[1], second);
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.apply_audit_allow_result(&key, 2, Ok(0), window, cx);
        assert!(matches!(
            shell.status_message,
            Some(BannerMessage::AllowlistAlreadyPresent)
        ));
        assert_eq!(
            render_banner_message(&shell.i18n(), shell.status_message.as_ref().unwrap()),
            "The selected codes are already in the allowlist"
        );
    });
    let mut incoming = entry;
    incoming.codes = vec!["mel_python".into(), "mel_eval".into(), "mel_exec".into()];
    assert_eq!(add_user_allowlist_entry(&user, &incoming).unwrap(), 1);
    let merged = read_user_allowlist(&user).unwrap();
    assert_eq!(merged.entries[0].codes, ["mel_exec", "mel_python"]);
    assert_eq!(merged.entries[1], second);
    let bytes = fs::read(&user).unwrap();
    assert_eq!(add_user_allowlist_entry(&user, &incoming).unwrap(), 0);
    assert_eq!(fs::read(&user).unwrap(), bytes);
}

#[gpui::test]
fn audit_allow_result_after_dialog_closed_still_reloads(cx: &mut TestAppContext) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let user = dir.path().join("ExampleUser/allowlist.json");
    fs::write(&path, SCENE).unwrap();
    let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
    let old_fingerprint = shell.update_in(visual_cx, |shell, window, cx| {
        open_finding(
            shell,
            current_row(&path, &shell.audit_plan),
            AuditFindingCode::MelExec,
            window,
            cx,
        );
        shell.audit_plan_fingerprint.clone()
    });
    visual_cx.run_until_parked();
    let observed = Rc::new(RefCell::new(false));
    shell.update_in(visual_cx, |shell, window, cx| {
        let observed = observed.clone();
        cx.observe_self(move |shell, _| {
            if let Some(message @ BannerMessage::AllowlistAdded { count: 1 }) =
                &shell.status_message
            {
                assert_eq!(
                    render_banner_message(&shell.i18n(), message),
                    "Added to the allowlist: 1 code(s)"
                );
                assert_ne!(shell.audit_plan_fingerprint, old_fingerprint);
                assert!(!shell.audit_allow_in_flight);
                assert!(shell.audit_detail_dialog.is_none());
                *observed.borrow_mut() = true;
            }
        })
        .detach();
        shell.open_audit_allow_form(window, cx);
        shell.submit_audit_allow_form(window, cx);
        shell.clear_audit_detail_dialog_state(cx);
        window.close_dialog(cx);
        assert!(shell.audit_allow_in_flight);
    });
    visual_cx.run_until_parked();
    assert!(*observed.borrow());
    assert_eq!(
        read_user_allowlist(&user).unwrap().entries[0].codes,
        ["mel_exec"]
    );
}

#[gpui::test]
fn audit_allow_panel_state_and_stale_results(cx: &mut TestAppContext) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("TestScene.ma");
    let user = dir.path().join("ExampleUser/allowlist.json");
    fs::write(&path, SCENE).unwrap();
    let (shell, visual_cx) = open_shell(cx, dir.path(), &user);
    let key = shell.update_in(visual_cx, |shell, window, cx| {
        open_finding(
            shell,
            current_row(&path, &shell.audit_plan),
            AuditFindingCode::MelExec,
            window,
            cx,
        )
    });
    visual_cx.run_until_parked();
    shell.update_in(visual_cx, |shell, window, cx| {
        shell.workspace_scan_state.in_flight = true;
        shell.audit_detail_dialog.as_mut().unwrap().active_tab = AuditDetailTab::Details;
        shell.open_audit_allow_form(window, cx);
        let form = shell
            .audit_detail_dialog
            .as_mut()
            .unwrap()
            .allow_form
            .as_mut()
            .unwrap();
        form.reason_input.update(cx, |input, cx| {
            input.set_value("Example reason", window, cx)
        });
        form.request = Some(10);
        form.error = Some(AllowAddError::AuditFailed("Example error".into()));
        let expected = form.clone();
        let assert_form_unchanged = |shell: &GuiShell, cx: &App| {
            let form = shell
                .audit_detail_dialog
                .as_ref()
                .unwrap()
                .allow_form
                .as_ref()
                .unwrap();
            assert_eq!(form.request, expected.request);
            assert_eq!(form.error, expected.error);
            assert_eq!(form.checked_codes, expected.checked_codes);
            assert_eq!(form.reason_input, expected.reason_input);
            assert_eq!(
                form.reason_input.read(cx).value().as_ref(),
                "Example reason"
            );
        };
        let mut other_key = key.clone();
        other_key.row_id += 1;
        for (result_key, result_request, code) in
            [(key.clone(), 11, "mel_python"), (other_key, 10, "mel_eval")]
        {
            shell.audit_allow_in_flight = true;
            shell.apply_audit_allow_result(
                &result_key,
                result_request,
                Err(AllowAddError::AuditFailed("Sample error".into())),
                window,
                cx,
            );
            assert_form_unchanged(shell, cx);

            let mut entry = request(
                &shell.rows[0],
                AuditFindingCode::MelExec,
                &user,
                &shell.audit_plan,
                shell.audit_allowlist.clone(),
            )
            .entry;
            entry.codes = vec![code.into()];
            let new_codes = add_user_allowlist_entry(&user, &entry).unwrap();
            assert_eq!(new_codes, 1);
            let old_fingerprint = shell.audit_plan_fingerprint.clone();
            let expected_plan =
                gui_audit_plan(load_allowlists(None, Some(&user)).allowlist).unwrap();
            shell.audit_allow_in_flight = true;
            shell.apply_audit_allow_result(&result_key, result_request, Ok(new_codes), window, cx);
            assert_form_unchanged(shell, cx);
            assert_ne!(shell.audit_plan_fingerprint, old_fingerprint);
            assert_eq!(
                shell.audit_plan_fingerprint,
                fingerprint_audit_plan(&expected_plan)
            );
            assert!(matches!(
                shell.status_message,
                Some(BannerMessage::AllowlistAdded { count: 1 })
            ));
            assert_eq!(
                render_banner_message(&shell.i18n(), shell.status_message.as_ref().unwrap()),
                "Added to the allowlist: 1 code(s)"
            );
            assert!(!shell.audit_allow_in_flight);
        }
        shell.rows[0].mark_analysis_stale();
        assert_eq!(
            shell
                .audit_detail_allow_disabled_reason()
                .map(|reason| shell.i18n().text(reason)),
            Some("Re-audit this file before allowing this finding.".into()),
        );
        shell.audit_allow_in_flight = true;
        cx.notify();
    });
    let cancel = visual_cx
        .debug_bounds("audit-allow-cancel")
        .expect("panel Cancel button");
    visual_cx.simulate_click(cancel.center(), Modifiers::default());
    shell.update_in(visual_cx, |shell, window, cx| {
        let state = shell.audit_detail_dialog.as_ref().unwrap();
        assert!(state.allow_form.is_none());
        assert_eq!(state.active_tab, AuditDetailTab::Details);
        assert!(shell.audit_allow_in_flight);
        assert!(window.has_active_dialog(cx));
        shell.rows[0].analyzed_audit_mode = Some(shell.state.audit_mode);
        shell.open_audit_allow_form(window, cx);
        assert!(
            shell
                .audit_detail_dialog
                .as_ref()
                .unwrap()
                .allow_form
                .is_some()
        );
        let row = &mut shell.rows[0];
        row.set_audit_report(row.audit_report.clone(), row.audit_file_state);
        shell.sync_audit_detail_dialog_inputs(window, cx);
        assert!(
            shell
                .audit_detail_dialog
                .as_ref()
                .unwrap()
                .allow_form
                .is_none()
        );
    });
}
