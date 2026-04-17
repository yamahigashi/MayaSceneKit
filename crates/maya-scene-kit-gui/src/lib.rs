mod gui;
mod i18n;
mod menu_bar;
mod model;
mod persistence;

pub use gui::run;
pub use persistence::{
    default_analysis_cache_root, default_state_path, load_persisted_state, save_persisted_state,
};
