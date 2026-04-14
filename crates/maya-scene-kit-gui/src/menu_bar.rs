use gpui::{
    Action, AnyElement, App, Context, Corner, DismissEvent, Entity, FocusHandle, Focusable,
    IntoElement, KeyBinding, MouseButton, MouseDownEvent, OwnedMenu, OwnedMenuItem, ParentElement,
    Pixels, Render, SharedString, Subscription, Window, actions, anchored, deferred, div,
    prelude::*, px, rgb,
};
use gpui_component::{
    Icon, IconName, Sizable, h_flex,
    menu::{AppMenuBar, PopupMenu, PopupMenuItem},
};

use crate::gui::{
    BORDER, MenuEditRedoUnavailable, MenuEditUndoUnavailable, MenuRecentFolder0, MenuRecentFolder1,
    MenuRecentFolder2, MenuRecentFolder3, MenuRecentFolder4, MenuRecentFolder5, MenuRecentFolder6,
    MenuRecentFolder7, MenuRecentFolder8, MenuRecentFolder9, MenuRecentFolderUnavailable,
    MenuRemoveRecentFolderByPath, TEXT,
};

actions!(
    windows_menu_bar,
    [MenuBarCancel, MenuBarSelectLeft, MenuBarSelectRight]
);

const CONTEXT: &str = "WindowsMenuBar";
const MENU_BAR_BG: u32 = 0xf7f7f7;
const MENU_HOVER_BG: u32 = 0xececec;
const MENU_ACTIVE_BG: u32 = 0xdbe8f8;
const MENU_ACTIVE_BORDER: u32 = 0xb8cbe6;

pub fn init(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("escape", MenuBarCancel, Some(CONTEXT)),
        KeyBinding::new("left", MenuBarSelectLeft, Some(CONTEXT)),
        KeyBinding::new("right", MenuBarSelectRight, Some(CONTEXT)),
    ]);
}

#[derive(Clone)]
pub enum TopMenuBar {
    Windows(Entity<WindowsMenuBar>),
    Default(Entity<AppMenuBar>),
}

impl TopMenuBar {
    pub fn new(window: &mut Window, cx: &mut App) -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows(WindowsMenuBar::new(window, cx.focus_handle(), cx))
        } else {
            Self::Default(AppMenuBar::new(window, cx))
        }
    }

    pub fn element(&self) -> AnyElement {
        match self {
            Self::Windows(menu_bar) => menu_bar.clone().into_any_element(),
            Self::Default(menu_bar) => menu_bar.clone().into_any_element(),
        }
    }
}

pub struct WindowsMenuBar {
    menus: Vec<Entity<WindowsMenu>>,
    selected_ix: Option<usize>,
    action_context: FocusHandle,
}

impl WindowsMenuBar {
    pub fn new(window: &mut Window, action_context: FocusHandle, cx: &mut App) -> Entity<Self> {
        cx.new(|cx| {
            let menu_bar = cx.entity();
            let menus = cx
                .get_menus()
                .unwrap_or_default()
                .iter()
                .enumerate()
                .map(|(ix, menu)| {
                    WindowsMenu::new(
                        ix,
                        menu,
                        menu_bar.clone(),
                        action_context.clone(),
                        window,
                        cx,
                    )
                })
                .collect();

            Self {
                menus,
                selected_ix: None,
                action_context,
            }
        })
    }

    pub(crate) fn reload_from_app(
        &mut self,
        window: &mut Window,
        action_context: FocusHandle,
        cx: &mut Context<Self>,
    ) {
        self.action_context = action_context.clone();
        let menu_bar = cx.entity();
        self.menus = cx
            .get_menus()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(ix, menu)| {
                WindowsMenu::new(
                    ix,
                    menu,
                    menu_bar.clone(),
                    action_context.clone(),
                    window,
                    cx,
                )
            })
            .collect();
        self.selected_ix = None;
        cx.notify();
    }

    fn on_move_left(&mut self, _: &MenuBarSelectLeft, window: &mut Window, cx: &mut Context<Self>) {
        let Some(selected_ix) = self.selected_ix else {
            return;
        };

        let new_ix = if selected_ix == 0 {
            self.menus.len().saturating_sub(1)
        } else {
            selected_ix.saturating_sub(1)
        };
        self.set_selected_index(Some(new_ix), window, cx);
    }

    fn on_move_right(
        &mut self,
        _: &MenuBarSelectRight,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(selected_ix) = self.selected_ix else {
            return;
        };

        let new_ix = if selected_ix + 1 >= self.menus.len() {
            0
        } else {
            selected_ix + 1
        };
        self.set_selected_index(Some(new_ix), window, cx);
    }

    fn on_cancel(&mut self, _: &MenuBarCancel, window: &mut Window, cx: &mut Context<Self>) {
        self.set_selected_index(None, window, cx);
    }

    fn set_selected_index(&mut self, ix: Option<usize>, _: &mut Window, cx: &mut Context<Self>) {
        self.selected_ix = ix;
        cx.notify();
    }

    fn has_activated_menu(&self) -> bool {
        self.selected_ix.is_some()
    }
}

impl Render for WindowsMenuBar {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        h_flex()
            .id("windows-menu-bar")
            .key_context(CONTEXT)
            .gap_x_0()
            .px_1()
            .py_0p5()
            .bg(rgb(MENU_BAR_BG))
            .overflow_x_scroll()
            .on_action(cx.listener(Self::on_move_left))
            .on_action(cx.listener(Self::on_move_right))
            .on_action(cx.listener(Self::on_cancel))
            .children(self.menus.clone())
    }
}

struct WindowsMenu {
    menu_bar: Entity<WindowsMenuBar>,
    action_context: FocusHandle,
    ix: usize,
    name: SharedString,
    menu: OwnedMenu,
    popup_menu: Option<Entity<PopupMenu>>,
    _subscription: Option<Subscription>,
}

impl WindowsMenu {
    fn new(
        ix: usize,
        menu: &OwnedMenu,
        menu_bar: Entity<WindowsMenuBar>,
        action_context: FocusHandle,
        _: &mut Window,
        cx: &mut Context<WindowsMenuBar>,
    ) -> Entity<Self> {
        let name = menu.name.clone();
        cx.new(|_| Self {
            menu_bar,
            action_context,
            ix,
            name,
            menu: menu.clone(),
            popup_menu: None,
            _subscription: None,
        })
    }

    fn build_popup_menu(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Entity<PopupMenu> {
        let popup_menu = match self.popup_menu.as_ref() {
            None => {
                let items = self.menu.items.clone();
                let action_context = self.action_context.clone();
                let popup_menu = PopupMenu::build(window, cx, |menu, window, cx| {
                    let menu = menu.action_context(action_context);
                    build_popup_from_owned_menu(menu, items, window, cx)
                });
                popup_menu.read(cx).focus_handle(cx).focus(window);
                self._subscription =
                    Some(cx.subscribe_in(&popup_menu, window, Self::handle_dismiss));
                self.popup_menu = Some(popup_menu.clone());
                popup_menu
            }
            Some(menu) => menu.clone(),
        };

        let focus_handle = popup_menu.read(cx).focus_handle(cx);
        if !focus_handle.contains_focused(window, cx) {
            focus_handle.focus(window);
        }

        popup_menu
    }

    fn handle_dismiss(
        &mut self,
        _: &Entity<PopupMenu>,
        _: &DismissEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self._subscription.take();
        self.popup_menu.take();
        self.menu_bar.update(cx, |state, cx| {
            state.on_cancel(&MenuBarCancel, window, cx);
        });
    }

    fn handle_trigger_mouse_down(
        &mut self,
        _: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let is_selected = self.menu_bar.read(cx).selected_ix == Some(self.ix);
        window.prevent_default();
        cx.stop_propagation();

        self.menu_bar.update(cx, |state, cx| {
            let new_ix = if is_selected { None } else { Some(self.ix) };
            state.set_selected_index(new_ix, window, cx);
        });
    }

    fn handle_hover(&mut self, hovered: &bool, window: &mut Window, cx: &mut Context<Self>) {
        if !*hovered {
            return;
        }

        if !self.menu_bar.read(cx).has_activated_menu() {
            return;
        }

        self.menu_bar.update(cx, |state, cx| {
            state.set_selected_index(Some(self.ix), window, cx);
        });
    }
}

impl Render for WindowsMenu {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let is_selected = self.menu_bar.read(cx).selected_ix == Some(self.ix);

        div()
            .id(("windows-menu", self.ix))
            .relative()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_center()
                    .h(px(22.))
                    .px_2()
                    .text_sm()
                    .text_color(rgb(TEXT))
                    .bg(if is_selected {
                        rgb(MENU_ACTIVE_BG)
                    } else {
                        rgb(MENU_BAR_BG)
                    })
                    .border_1()
                    .border_color(if is_selected {
                        rgb(MENU_ACTIVE_BORDER)
                    } else {
                        rgb(MENU_BAR_BG)
                    })
                    .when(!is_selected, |this| {
                        this.hover(|this| this.bg(rgb(MENU_HOVER_BG)).border_color(rgb(BORDER)))
                    })
                    .child(self.name.clone())
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(Self::handle_trigger_mouse_down),
                    ),
            )
            .on_hover(cx.listener(Self::handle_hover))
            .when(is_selected, |this| {
                this.child(deferred(
                    anchored()
                        .anchor(Corner::TopLeft)
                        .snap_to_window_with_margin(px(8.))
                        .child(
                            div()
                                .size_full()
                                .occlude()
                                .top_1()
                                .child(self.build_popup_menu(window, cx)),
                        ),
                ))
            })
    }
}

fn build_popup_from_owned_menu(
    mut popup: PopupMenu,
    items: Vec<OwnedMenuItem>,
    window: &mut Window,
    cx: &mut Context<PopupMenu>,
) -> PopupMenu {
    let popup_view = cx.entity();
    popup.replace_menu_items(popup_items_from_owned_menu(items, popup_view, window, cx));
    popup
}

fn popup_items_from_owned_menu(
    items: Vec<OwnedMenuItem>,
    popup_view: Entity<PopupMenu>,
    window: &mut Window,
    cx: &mut Context<PopupMenu>,
) -> Vec<PopupMenuItem> {
    items
        .into_iter()
        .filter_map(|item| popup_item_from_owned_menu(item, popup_view.clone(), window, cx))
        .collect()
}

fn popup_item_from_owned_menu(
    item: OwnedMenuItem,
    popup_view: Entity<PopupMenu>,
    window: &mut Window,
    cx: &mut Context<PopupMenu>,
) -> Option<PopupMenuItem> {
    match item {
        OwnedMenuItem::Action {
            name,
            action,
            checked,
            ..
        } => {
            let disabled = action_is_explicitly_disabled(action.as_ref());
            Some(
                if let Some(index) = recent_folder_action_index(action.as_ref()) {
                    recent_folder_popup_item(name.into(), action, checked, index, popup_view)
                        .disabled(disabled)
                } else {
                    PopupMenuItem::new(name)
                        .checked(checked)
                        .disabled(disabled)
                        .action(action)
                },
            )
        }
        OwnedMenuItem::Separator => Some(PopupMenuItem::separator()),
        OwnedMenuItem::Submenu(submenu) => {
            let submenu_name = submenu.name;
            let submenu_items = submenu.items.clone();
            let is_recent_folder = owned_items_are_recent_folder_menu(&submenu_items);
            let submenu_entity = PopupMenu::build(window, cx, move |menu, window, cx| {
                let menu = if is_recent_folder {
                    menu.min_w(recent_folder_popup_min_width(window))
                        .max_w(recent_folder_popup_max_width(window))
                } else {
                    menu
                };
                build_popup_from_owned_menu(menu, submenu_items.clone(), window, cx)
            });
            Some(PopupMenuItem::submenu(submenu_name, submenu_entity))
        }
        OwnedMenuItem::SystemMenu(_) => None,
    }
}

fn recent_folder_popup_item(
    name: SharedString,
    action: Box<dyn Action>,
    checked: bool,
    index: usize,
    popup_view: Entity<PopupMenu>,
) -> PopupMenuItem {
    const REMOVE_BUTTON_SIZE: Pixels = px(18.);

    let removed_path = name.to_string();
    let remove_action = MenuRemoveRecentFolderByPath {
        path: removed_path.clone(),
    };
    PopupMenuItem::element(move |_window, _cx| {
        h_flex()
            .w_full()
            .flex_1()
            .min_w_0()
            .items_center()
            .justify_between()
            .gap_3()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .child(div().min_w_0().truncate().child(name.clone())),
            )
            .child(
                h_flex()
                    .id(SharedString::from(format!("recent-folder-remove-{index}")))
                    .flex_none()
                    .w(REMOVE_BUTTON_SIZE)
                    .h(REMOVE_BUTTON_SIZE)
                    .rounded_full()
                    .items_center()
                    .justify_center()
                    .text_color(rgb(TEXT))
                    .on_mouse_down(MouseButton::Left, |_, window, cx| {
                        window.prevent_default();
                        cx.stop_propagation();
                    })
                    .on_click({
                        let popup_view = popup_view.clone();
                        let removed_path = removed_path.clone();
                        let remove_action = remove_action.clone();
                        move |_, window, cx| {
                            window.prevent_default();
                            cx.stop_propagation();
                            window.dispatch_action(Box::new(remove_action.clone()), cx);
                            if let Some(items) = current_recent_folder_owned_items(cx) {
                                let popup_view_for_update = popup_view.clone();
                                let removed_path_for_update = removed_path.clone();
                                popup_view.update(cx, move |popup, cx| {
                                    popup.replace_menu_items(
                                        recent_folder_popup_items_after_local_removal(
                                            items,
                                            &removed_path_for_update,
                                            popup_view_for_update.clone(),
                                        ),
                                    );
                                    cx.notify();
                                });
                            }
                        }
                    })
                    .hover(|this| this.bg(rgb(BORDER)))
                    .child(Icon::new(IconName::Close).xsmall()),
            )
    })
    .checked(checked)
    .action(action)
}

fn recent_folder_popup_items_after_local_removal(
    items: Vec<OwnedMenuItem>,
    removed_path: &str,
    popup_view: Entity<PopupMenu>,
) -> Vec<PopupMenuItem> {
    recent_folder_popup_items_from_owned_menu(
        items
            .into_iter()
            .filter(|item| match item {
                OwnedMenuItem::Action { name, action, .. } => {
                    !(recent_folder_action_index(action.as_ref()).is_some() && name == removed_path)
                }
                _ => true,
            })
            .collect(),
        popup_view,
    )
}

fn recent_folder_popup_items_from_owned_menu(
    items: Vec<OwnedMenuItem>,
    popup_view: Entity<PopupMenu>,
) -> Vec<PopupMenuItem> {
    items
        .into_iter()
        .filter_map(|item| match item {
            OwnedMenuItem::Action {
                name,
                action,
                checked,
                ..
            } => {
                if let Some(index) = recent_folder_action_index(action.as_ref()) {
                    Some(recent_folder_popup_item(
                        name.into(),
                        action,
                        checked,
                        index,
                        popup_view.clone(),
                    ))
                } else if action_is_explicitly_disabled(action.as_ref()) {
                    Some(PopupMenuItem::new(name).disabled(true).action(action))
                } else {
                    None
                }
            }
            OwnedMenuItem::Separator => Some(PopupMenuItem::separator()),
            _ => None,
        })
        .collect()
}

fn recent_folder_action_index(action: &dyn Action) -> Option<usize> {
    if action.as_any().is::<MenuRecentFolder0>() {
        Some(0)
    } else if action.as_any().is::<MenuRecentFolder1>() {
        Some(1)
    } else if action.as_any().is::<MenuRecentFolder2>() {
        Some(2)
    } else if action.as_any().is::<MenuRecentFolder3>() {
        Some(3)
    } else if action.as_any().is::<MenuRecentFolder4>() {
        Some(4)
    } else if action.as_any().is::<MenuRecentFolder5>() {
        Some(5)
    } else if action.as_any().is::<MenuRecentFolder6>() {
        Some(6)
    } else if action.as_any().is::<MenuRecentFolder7>() {
        Some(7)
    } else if action.as_any().is::<MenuRecentFolder8>() {
        Some(8)
    } else if action.as_any().is::<MenuRecentFolder9>() {
        Some(9)
    } else {
        None
    }
}

fn action_is_explicitly_disabled(action: &dyn Action) -> bool {
    action.as_any().is::<MenuEditUndoUnavailable>()
        || action.as_any().is::<MenuEditRedoUnavailable>()
        || action.as_any().is::<MenuRecentFolderUnavailable>()
}

#[cfg(test)]
mod tests {
    use super::action_is_explicitly_disabled;
    use crate::gui::{
        MenuEditRedoUnavailable, MenuEditUndoUnavailable, MenuRecentFolderUnavailable,
        MenuSelectFolder,
    };

    #[test]
    fn explicit_disabled_action_detection_only_flags_unavailable_actions() {
        assert!(action_is_explicitly_disabled(&MenuEditUndoUnavailable));
        assert!(action_is_explicitly_disabled(&MenuEditRedoUnavailable));
        assert!(action_is_explicitly_disabled(&MenuRecentFolderUnavailable));
        assert!(!action_is_explicitly_disabled(&MenuSelectFolder));
    }
}

fn is_recent_folder_action(action: &dyn Action) -> bool {
    recent_folder_action_index(action).is_some()
        || action.as_any().is::<MenuRecentFolderUnavailable>()
}

fn owned_items_are_recent_folder_menu(items: &[OwnedMenuItem]) -> bool {
    !items.is_empty()
        && items.iter().all(|item| match item {
            OwnedMenuItem::Action { action, .. } => is_recent_folder_action(action.as_ref()),
            OwnedMenuItem::Separator => true,
            _ => false,
        })
}

fn current_recent_folder_owned_items(cx: &App) -> Option<Vec<OwnedMenuItem>> {
    cx.get_menus().and_then(|menus| {
        menus.into_iter().find_map(|menu| {
            menu.items.into_iter().find_map(|item| match item {
                OwnedMenuItem::Submenu(submenu)
                    if owned_items_are_recent_folder_menu(&submenu.items) =>
                {
                    Some(submenu.items)
                }
                _ => None,
            })
        })
    })
}

fn recent_folder_popup_max_width(window: &Window) -> Pixels {
    (window.window_bounds().get_bounds().size.width - px(48.))
        .max(px(360.))
        .min(px(1200.))
}

fn recent_folder_popup_min_width(window: &Window) -> Pixels {
    recent_folder_popup_max_width(window).min(px(640.))
}
