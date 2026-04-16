use std::collections::BTreeMap;

use super::super::*;

const WORKSPACE_PATH_PREFIX_MUTED: u32 = 0xa3a19e;

pub(in crate::gui) fn path_table_columns(
    show_scene_column: bool,
    sort: PathTableSort,
) -> Vec<Column> {
    let mut columns = Vec::new();
    columns.push(
        Column::new("kind", "")
            .width(px(88.0))
            .resizable(false)
            .sortable(),
    );
    if show_scene_column {
        columns.push(
            Column::new("scene", "Scene")
                .width(px(300.0))
                .resizable(true)
                .sortable()
                .sort(if sort.key == PathSortKey::Scene {
                    sort.direction
                } else {
                    ColumnSort::Default
                }),
        );
    }
    columns.push(
        Column::new("node", "Node")
            .width(px(220.0))
            .resizable(true)
            .sortable()
            .sort(if sort.key == PathSortKey::Node {
                sort.direction
            } else {
                ColumnSort::Default
            }),
    );
    columns.push(
        Column::new("path", "Path")
            .width(px(700.0))
            .resizable(true)
            .sortable()
            .sort(if sort.key == PathSortKey::Path {
                sort.direction
            } else {
                ColumnSort::Default
            }),
    );
    columns
}

pub(in crate::gui) fn merge_column_widths(
    existing: &[Column],
    mut next: Vec<Column>,
) -> Vec<Column> {
    let widths_by_key = existing
        .iter()
        .map(|column| (column.key.clone(), column.width))
        .collect::<BTreeMap<_, _>>();
    for column in &mut next {
        if let Some(width) = widths_by_key.get(&column.key) {
            column.width = *width;
        }
    }
    next
}

pub(in crate::gui) fn apply_persisted_column_widths(
    mut columns: Vec<Column>,
    persisted_widths: &[PersistedTableColumnWidth],
) -> Vec<Column> {
    let widths_by_key = persisted_widths
        .iter()
        .map(|width| (width.key.as_str(), px(width.width_px as f32)))
        .collect::<BTreeMap<_, _>>();
    for column in &mut columns {
        if let Some(width) = widths_by_key.get(column.key.as_ref()) {
            column.width = *width;
        }
    }
    columns
}

pub(in crate::gui) fn persisted_column_widths(
    columns: &[Column],
) -> Vec<PersistedTableColumnWidth> {
    columns
        .iter()
        .map(|column| PersistedTableColumnWidth {
            key: column.key.to_string(),
            width_px: u32::from(column.width),
        })
        .collect()
}

pub(in crate::gui) fn update_path_sort_columns(
    columns: &mut [Column],
    show_scene_column: bool,
    sort: PathTableSort,
) {
    for (col_ix, column) in columns.iter_mut().enumerate() {
        let Some(key) = path_sort_key_for_col_ix(col_ix, show_scene_column) else {
            continue;
        };
        if column.sort.is_some() {
            column.sort = Some(if key == sort.key {
                sort.direction
            } else {
                ColumnSort::Default
            });
        }
    }
}

pub(in crate::gui) fn file_table_cell_container() -> Div {
    div().size_full().flex().items_center().min_w_0()
}

pub(in crate::gui) fn audit_table_columns(
    locale: SupportedLocale,
    sort: AuditTableSort,
) -> Vec<Column> {
    let i18n = I18n::new(locale);
    vec![
        Column::new("scene", i18n.text("table.scene"))
            .width(px(220.0))
            .sort(if sort.key == AuditSortKey::Scene {
                sort.direction
            } else {
                ColumnSort::Default
            }),
        Column::new("severity", i18n.text("table.severity"))
            .width(px(130.0))
            .sort(if sort.key == AuditSortKey::Severity {
                sort.direction
            } else {
                ColumnSort::Default
            }),
        Column::new("summary", i18n.text("table.summary"))
            .width(px(560.0))
            .sort(if sort.key == AuditSortKey::Summary {
                sort.direction
            } else {
                ColumnSort::Default
            }),
        Column::new("code", i18n.text("table.code"))
            .width(px(160.0))
            .sort(if sort.key == AuditSortKey::Code {
                sort.direction
            } else {
                ColumnSort::Default
            }),
        Column::new("sink", i18n.text("table.sink"))
            .width(px(160.0))
            .sort(if sort.key == AuditSortKey::Sink {
                sort.direction
            } else {
                ColumnSort::Default
            }),
    ]
}

pub(in crate::gui) fn audit_table_text_cell(text: String) -> Div {
    file_table_text_cell(text)
}

pub(in crate::gui) fn audit_table_muted_text_cell(text: String) -> Div {
    file_table_text_cell(text).text_color(rgb(MUTED))
}

pub(in crate::gui) fn file_table_text_cell(text: String) -> Div {
    div()
        .flex_1()
        .min_w_0()
        .text_sm()
        .overflow_hidden()
        .whitespace_nowrap()
        .truncate()
        .child(text)
}

pub(in crate::gui) fn file_table_muted_text_cell(text: String) -> Div {
    file_table_text_cell(text).text_color(rgb(MUTED))
}

pub(in crate::gui) fn path_table_cell(
    text: String,
    value_style: Option<ScenePathValueStyle>,
    owner_deleted: bool,
) -> Div {
    div()
        .size_full()
        .flex()
        .items_center()
        .min_w_0()
        .child(path_table_text(text, value_style, owner_deleted))
}

pub(in crate::gui) fn path_table_text(
    text: String,
    value_style: Option<ScenePathValueStyle>,
    owner_deleted: bool,
) -> Div {
    let highlights = path_text_highlights(&text, value_style, owner_deleted);
    div()
        .flex_1()
        .min_w_0()
        .text_sm()
        .when(owner_deleted, |this| this.text_color(rgb(MUTED)))
        .overflow_hidden()
        .whitespace_nowrap()
        .truncate()
        .child(
            StyledText::new(text).when_some(highlights, |this, highlights| {
                this.with_highlights(highlights)
            }),
        )
}

pub(in crate::gui) fn path_text_highlights(
    text: &str,
    value_style: Option<ScenePathValueStyle>,
    owner_deleted: bool,
) -> Option<Vec<(std::ops::Range<usize>, HighlightStyle)>> {
    let workspace_highlights = workspace_prefix_highlights(text, value_style);
    let owner_deleted_highlights = owner_deleted.then(|| {
        vec![(
            0..text.len(),
            HighlightStyle {
                strikethrough: Some(StrikethroughStyle {
                    thickness: px(1.0),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]
    });
    match (workspace_highlights, owner_deleted_highlights) {
        (None, None) => None,
        (Some(highlights), None) | (None, Some(highlights)) => Some(highlights),
        (Some(base), Some(overlay)) => Some(gpui::combine_highlights(base, overlay).collect()),
    }
}

fn workspace_prefix_highlights(
    text: &str,
    value_style: Option<ScenePathValueStyle>,
) -> Option<Vec<(std::ops::Range<usize>, HighlightStyle)>> {
    if value_style != Some(ScenePathValueStyle::DoubleSlashWorkspaceRelative) {
        return None;
    }
    let (prefix, _suffix) = text.split_once("//")?;
    if prefix.is_empty() {
        return None;
    }
    let separator_start = prefix.len();
    let separator_end = separator_start + 2;
    Some(vec![
        (
            0..prefix.len(),
            HighlightStyle {
                color: Some(rgb(WORKSPACE_PATH_PREFIX_MUTED).into()),
                ..Default::default()
            },
        ),
        (
            separator_start..separator_end,
            HighlightStyle {
                font_weight: Some(FontWeight::BOLD),
                ..Default::default()
            },
        ),
    ])
}
