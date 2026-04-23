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

fn lookup(locale: SupportedLocale, key: &'static str) -> Option<&'static str> {
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
    fn catalogs_cover_expected_keys() {
        let en = I18n::new(SupportedLocale::English);
        let ja = I18n::new(SupportedLocale::Japanese);
        let zh = I18n::new(SupportedLocale::Chinese);
        for key in [
            "action.audit",
            "action.clean_selected",
            "action.clean_audit_context",
            "action.clean_file_context",
            "action.copy_source_text",
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
}
