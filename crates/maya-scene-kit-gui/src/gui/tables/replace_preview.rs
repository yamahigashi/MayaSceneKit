use super::*;

const REPLACE_PREVIEW_COLUMN_WIDTH: f32 = 420.0;
const REPLACE_PREVIEW_UNMATCHED_TEXT: u32 = 0x8f877d;

impl ReplacePreviewTableDelegate {
    pub(in crate::gui) fn new(locale: SupportedLocale, sort: ReplaceDialogSort) -> Self {
        Self {
            view: None,
            locale,
            rows: Vec::new(),
            sort,
            columns: replace_preview_columns(locale),
        }
    }

    pub(in crate::gui) fn set_view(&mut self, view: Entity<GuiShell>) {
        self.view = Some(view);
    }

    /// Returns true when the column definitions changed and the table must rebuild its
    /// column layout. Rebuilding while the user drags a column divider would discard the
    /// in-progress width, so row-only updates must not trigger it.
    pub(in crate::gui) fn sync(
        &mut self,
        rows: Vec<ReplaceDialogPreviewRow>,
        locale: SupportedLocale,
        sort: ReplaceDialogSort,
    ) -> bool {
        self.rows = rows;
        self.sort = sort;
        if self.locale == locale {
            return false;
        }
        self.locale = locale;
        self.columns = merge_column_widths(&self.columns, replace_preview_columns(locale));
        true
    }

    pub(in crate::gui) fn apply_widths(&mut self, widths: &[Pixels]) {
        for (column, width) in self.columns.iter_mut().zip(widths.iter().copied()) {
            column.width = width;
        }
    }

    pub(in crate::gui) fn row_count(&self) -> usize {
        self.rows.len()
    }

    #[cfg(test)]
    pub(in crate::gui) fn rows(&self) -> &[ReplaceDialogPreviewRow] {
        &self.rows
    }
}

fn replace_preview_columns(locale: SupportedLocale) -> Vec<Column> {
    let i18n = I18n::new(locale);
    vec![
        Column::new("before", i18n.text("label.before")).width(px(REPLACE_PREVIEW_COLUMN_WIDTH)),
        Column::new("after", i18n.text("label.after")).width(px(REPLACE_PREVIEW_COLUMN_WIDTH)),
    ]
}

fn replace_preview_sort_key_for_col_ix(col_ix: usize) -> Option<ReplaceDialogSortKey> {
    match col_ix {
        0 => Some(ReplaceDialogSortKey::Before),
        1 => Some(ReplaceDialogSortKey::After),
        _ => None,
    }
}

impl TableDelegate for ReplacePreviewTableDelegate {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> &Column {
        &self.columns[col_ix]
    }

    fn render_tr(
        &mut self,
        row_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> Stateful<Div> {
        let row = &self.rows[row_ix];
        let matched = row.before_value != row.after_value;
        with_row_state_mark(
            div().id(("replace-preview-row", row_ix)),
            matched.then_some(RowStateMark::Modified),
        )
    }

    fn render_th(
        &mut self,
        col_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let label = self.columns[col_ix].name.to_string();
        let Some(key) = replace_preview_sort_key_for_col_ix(col_ix) else {
            return div().child(label).into_any_element();
        };
        let indicator = if self.sort.key == key {
            match self.sort.direction {
                ColumnSort::Ascending => " ↑",
                ColumnSort::Descending => " ↓",
                ColumnSort::Default => "",
            }
        } else {
            ""
        };
        let cell = div()
            .size_full()
            .flex()
            .items_center()
            .min_w_0()
            .text_sm()
            .font_weight(FontWeight::BOLD)
            .child(
                div()
                    .min_w_0()
                    .truncate()
                    .child(format!("{label}{indicator}")),
            );
        let Some(view) = self.view.clone() else {
            return cell.into_any_element();
        };
        cell.cursor_pointer()
            .on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .on_mouse_up(MouseButton::Left, move |_, _, cx| {
                cx.stop_propagation();
                view.update(cx, |shell, cx| {
                    shell.toggle_replace_dialog_preview_sort(key, cx);
                });
            })
            .into_any_element()
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let row = &self.rows[row_ix];
        let matched = row.before_value != row.after_value;
        let text = if col_ix == 0 {
            row.before_value.clone()
        } else {
            row.after_value.clone()
        };
        div()
            .size_full()
            .flex()
            .items_center()
            .min_w_0()
            .text_sm()
            .text_color(rgb(if matched {
                TEXT
            } else {
                REPLACE_PREVIEW_UNMATCHED_TEXT
            }))
            .child(div().min_w_0().truncate().child(text))
    }
}
