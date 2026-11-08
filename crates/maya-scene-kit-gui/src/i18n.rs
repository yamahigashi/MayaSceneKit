use std::{collections::BTreeMap, sync::OnceLock};

use chrono::{DateTime, Local};

use crate::model::SupportedLocale;

pub struct I18n {
    locale: SupportedLocale,
}

impl I18n {
    pub fn new(locale: SupportedLocale) -> Self {
        Self { locale }
    }

    pub fn locale(&self) -> SupportedLocale {
        self.locale
    }

    pub fn text(&self, key: &'static str) -> String {
        lookup(self.locale, key)
            .or_else(|| lookup(SupportedLocale::English, key))
            .unwrap_or(key)
            .to_string()
    }

    pub fn try_text(&self, key: &str) -> Option<String> {
        lookup(self.locale, key)
            .or_else(|| lookup(SupportedLocale::English, key))
            .map(str::to_string)
    }

    pub fn format(&self, key: &'static str, replacements: &[(&str, String)]) -> String {
        let mut rendered = self.text(key);
        for (name, value) in replacements {
            rendered = rendered.replace(&format!("{{{name}}}"), value);
        }
        rendered
    }

    pub fn format_modified(&self, time: Option<std::time::SystemTime>) -> String {
        let Some(time) = time else {
            return "-".to_string();
        };
        let datetime: DateTime<Local> = DateTime::from(time);
        datetime.format("%Y-%m-%d %H:%M").to_string()
    }

    pub fn format_timestamp(&self, time: DateTime<Local>) -> String {
        time.format("%Y-%m-%d %H:%M").to_string()
    }

    pub fn format_bytes(&self, size: u64) -> String {
        const MB: f64 = 1024.0 * 1024.0;
        format!("{:.2} MB", size as f64 / MB)
    }
}

fn lookup(locale: SupportedLocale, key: &str) -> Option<&'static str> {
    let catalog = match locale {
        SupportedLocale::English => english_catalog(),
        SupportedLocale::Chinese => chinese_catalog(),
        SupportedLocale::Japanese => japanese_catalog(),
    };
    catalog.get(key).map(String::as_str)
}

fn english_catalog() -> &'static BTreeMap<String, String> {
    static CATALOG: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../locales/en.json")).expect("valid English catalog")
    })
}

fn japanese_catalog() -> &'static BTreeMap<String, String> {
    static CATALOG: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../locales/ja.json")).expect("valid Japanese catalog")
    })
}

fn chinese_catalog() -> &'static BTreeMap<String, String> {
    static CATALOG: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../locales/cn.json")).expect("valid Chinese catalog")
    })
}

#[cfg(test)]
mod tests {
    use super::I18n;
    use crate::model::SupportedLocale;

    #[test]
    fn allowlist_catalogs_contain_exact_translations() {
        let expected = [
            (
                "settings.reload_allowlists",
                [
                    "Reload allowlists",
                    "許可リストを再読み込み",
                    "重新加载允许列表",
                ],
            ),
            (
                "banner.allowlist_load_failed",
                [
                    "Could not load allowlist {path}: {error}",
                    "許可リストを読み込めませんでした: {path}: {error}",
                    "无法加载允许列表 {path}: {error}",
                ],
            ),
            (
                "banner.allowlists_reloaded",
                [
                    "Reloaded allowlists: {count} entries",
                    "許可リストを再読み込みしました: {count} 件",
                    "已重新加载允许列表：{count} 项",
                ],
            ),
            (
                "audit_table.show_allowed",
                [
                    "Show allowed ({count})",
                    "許可済みを表示 ({count})",
                    "显示已允许项 ({count})",
                ],
            ),
            ("label.allowed", ["Allowed", "許可済み", "已允许"]),
            ("label.audit_detail.allowed", ["Allowed", "許可", "允许"]),
            (
                "label.audit_detail.allow_hash",
                ["Allow hash", "許可ハッシュ", "允许哈希"],
            ),
            (
                "audit_value.allowlist_source.app",
                ["Distributed (app)", "管理者配布 (app)", "管理员分发 (app)"],
            ),
            (
                "audit_value.allowlist_source.user",
                ["User (user)", "ユーザー (user)", "用户 (user)"],
            ),
            (
                "banner.allowlists_stale_rows",
                [
                    "{count} file(s) need re-audit; files with unsaved edits update after saving",
                    "{count} 件のファイルは再監査が必要です（未保存の編集があるファイルは保存後に更新されます）",
                    "{count} 个文件需要重新审核（有未保存编辑的文件将在保存后更新）",
                ],
            ),
        ];
        for (index, catalog) in [
            super::english_catalog(),
            super::japanese_catalog(),
            super::chinese_catalog(),
        ]
        .into_iter()
        .enumerate()
        {
            for (key, values) in &expected {
                assert_eq!(
                    catalog.get(*key).map(String::as_str),
                    Some(values[index]),
                    "{key}"
                );
            }
        }
    }

    #[test]
    fn catalogs_cover_expected_keys() {
        let en = I18n::new(SupportedLocale::English);
        let ja = I18n::new(SupportedLocale::Japanese);
        let zh = I18n::new(SupportedLocale::Chinese);
        for key in [
            "action.audit",
            "action.clean_selected",
            "action.clean_audit_context",
            "action.clean_file_context",
            "action.delete_ui_configuration_script_node",
            "action.reload_folder",
            "tab.audit_detail_code",
            "tab.audit_detail_details",
            "action.close",
            "action.copy_details",
            "label.audit_detail.rule_id",
            "label.audit_detail.sink",
            "label.audit_detail.node",
            "label.audit_detail.attribute",
            "label.audit_detail.surface",
            "label.audit_detail.trigger",
            "label.audit_detail.language",
            "label.audit_detail.source",
            "label.audit_detail.line",
            "audit_value.trigger.unknown",
            "audit_value.trigger.manual",
            "audit_value.trigger.file_open",
            "audit_value.trigger.file_close",
            "audit_value.trigger.gui_open_close",
            "audit_value.trigger.render",
            "audit_value.trigger.time_changed",
            "audit_value.trigger.event_hook",
            "audit_value.surface.script_node_body",
            "audit_value.surface.file_command_callback",
            "audit_value.surface.node_attr_callback",
            "audit_value.surface.top_level_command",
            "audit_value.surface.top_level_proc_definition",
            "audit_value.surface.top_level_other_statement",
            "audit_value.surface.raw_chunk_text",
            "audit_value.language.mel",
            "audit_value.language.python",
            "audit_value.language.unknown",
            "audit_value.attribute.before",
            "audit_value.attribute.after",
            "audit_value.script_type.0",
            "audit_value.script_type.1",
            "audit_value.script_type.2",
            "audit_value.script_type.3",
            "audit_value.script_type.4",
            "audit_value.script_type.5",
            "audit_value.script_type.6",
            "audit_value.script_type.7",
            "audit_value.source_type.0",
            "audit_value.source_type.1",
            "action.reveal_in_explorer",
            "action.detail",
            "action.discard_edits_and_exit",
            "action.exit_application",
            "action.discard_changes",
            "action.return_to_application",
            "action.save",
            "action.save_all",
            "action.save_selected",
            "action.undo_selected",
            "empty.audit.filtered",
            "banner.select_files_first",
            "empty.audit.none",
            "empty.paths.parse_budget_blocked",
            "file_status.processing.analyze",
            "label.audit_notices",
            "label.evidence",
            "label.auto_analyze",
            "label.files",
            "layout.horizontal_split",
            "layout.vertical_split",
            "menu.edit",
            "menu.auto_analyze_parallelism",
            "menu.file",
            "menu.file_operations",
            "menu.layout",
            "menu.recent_folder",
            "settings.edit_ignored_folder_names",
            "settings.ignore_special_folders",
            "status.processing_count",
            "status.workspace_scan",
            "placeholder.audit_search",
            "placeholder.ignored_folder_name",
            "placeholder.path_search",
            "audit_table.dedup",
            "dialog.confirm_exit_application_description",
            "dialog.confirm_exit_application_title",
            "dialog.ignore_folder_names_title",
            "dialog.max_bytes_title",
            "label.ignored_folder_names",
            "banner.workspace_scan_in_progress",
            "path_type.reference",
            "settings.max_bytes",
            "severity.info",
            "severity.medium_plus",
            "table.attr",
            "table.modified",
            "placeholder.max_bytes",
        ] {
            assert_ne!(en.text(key), key);
            assert_ne!(ja.text(key), key);
            assert_ne!(zh.text(key), key);
        }
    }

    #[test]
    fn formatter_replaces_placeholders() {
        let en = I18n::new(SupportedLocale::English);
        assert_eq!(
            en.format(
                "banner.workspace_loaded",
                &[("count", "3".to_string()), ("path", "/tmp".to_string())]
            ),
            "Loaded 3 file(s) from /tmp"
        );
        assert_eq!(
            en.format(
                "banner.analyze_completed",
                &[
                    ("name", "scene.ma".to_string()),
                    ("elapsed", "1.25s".to_string()),
                ]
            ),
            "Analyzed scene.ma in 1.25s"
        );
        assert_eq!(
            en.format(
                "banner.workspace_auto_analyze_completed",
                &[
                    ("count", "12".to_string()),
                    ("elapsed", "2.50s".to_string()),
                ]
            ),
            "Workspace auto analyze completed for 12 file(s) in 2.50s"
        );
    }

    #[test]
    fn audit_detail_catalogs_directly_cover_all_keys_and_variants() {
        use maya_scene_kit_observe::scene::evidence::{
            ExecutionLanguage, ExecutionSurfaceKind, ExecutionTrigger,
        };
        let languages = [
            ExecutionLanguage::Mel,
            ExecutionLanguage::Python,
            ExecutionLanguage::Unknown,
        ];
        let triggers = [
            ExecutionTrigger::Unknown,
            ExecutionTrigger::Manual,
            ExecutionTrigger::FileOpen,
            ExecutionTrigger::FileClose,
            ExecutionTrigger::GuiOpenClose,
            ExecutionTrigger::Render,
            ExecutionTrigger::TimeChanged,
            ExecutionTrigger::EventHook,
        ];
        let surfaces = [
            ExecutionSurfaceKind::ScriptNodeBody,
            ExecutionSurfaceKind::FileCommandCallback,
            ExecutionSurfaceKind::NodeAttrCallback,
            ExecutionSurfaceKind::TopLevelCommand,
            ExecutionSurfaceKind::TopLevelProcDefinition,
            ExecutionSurfaceKind::TopLevelOtherStatement,
            ExecutionSurfaceKind::RawChunkText,
        ];
        for catalog in [
            super::english_catalog(),
            super::japanese_catalog(),
            super::chinese_catalog(),
        ] {
            for key in [
                "action.copy_code",
                "audit_detail.code_loading",
                "audit_detail.code_derived_parent",
                "audit_detail.code_not_found",
                "audit_detail.code_ambiguous",
                "audit_detail.code_load_failed",
                "audit_detail.code_unavailable",
                "audit_detail.code_file_changed",
                "audit_detail.code_too_large",
                "tab.audit_detail_code",
                "tab.audit_detail_details",
                "action.close",
                "action.copy_details",
                "label.audit_detail.rule_id",
                "label.audit_detail.sink",
                "label.audit_detail.node",
                "label.audit_detail.attribute",
                "label.audit_detail.surface",
                "label.audit_detail.trigger",
                "label.audit_detail.language",
                "label.audit_detail.source",
                "label.audit_detail.line",
                "audit_value.trigger.unknown",
                "audit_value.trigger.manual",
                "audit_value.trigger.file_open",
                "audit_value.trigger.file_close",
                "audit_value.trigger.gui_open_close",
                "audit_value.trigger.render",
                "audit_value.trigger.time_changed",
                "audit_value.trigger.event_hook",
                "audit_value.surface.script_node_body",
                "audit_value.surface.file_command_callback",
                "audit_value.surface.node_attr_callback",
                "audit_value.surface.top_level_command",
                "audit_value.surface.top_level_proc_definition",
                "audit_value.surface.top_level_other_statement",
                "audit_value.surface.raw_chunk_text",
                "audit_value.language.mel",
                "audit_value.language.python",
                "audit_value.language.unknown",
                "audit_value.attribute.before",
                "audit_value.attribute.after",
                "audit_value.script_type.0",
                "audit_value.script_type.1",
                "audit_value.script_type.2",
                "audit_value.script_type.3",
                "audit_value.script_type.4",
                "audit_value.script_type.5",
                "audit_value.script_type.6",
                "audit_value.script_type.7",
                "audit_value.source_type.0",
                "audit_value.source_type.1",
            ] {
                assert!(catalog.contains_key(key), "missing {key}");
            }
            for language in languages {
                assert!(
                    catalog.contains_key(&format!("audit_value.language.{}", language.as_str()))
                );
            }
            for trigger in triggers {
                assert!(catalog.contains_key(&format!("audit_value.trigger.{}", trigger.as_str())));
            }
            for surface in surfaces {
                assert!(catalog.contains_key(&format!("audit_value.surface.{}", surface.as_str())));
            }
            assert!(!catalog.contains_key("action.copy_source_text"));
        }
    }
}
