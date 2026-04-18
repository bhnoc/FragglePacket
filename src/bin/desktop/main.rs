//! FragglePacket Desktop - Dioxus GUI Frontend
//!
//! A native desktop application for network diagnostics with MTU discovery,
//! protocol testing, and packet fuzzing capabilities.

mod app;
mod state;
mod components;
mod theme;
mod test_registration;
mod window_manager;

fn main() {
    // Configure the desktop window
    let cfg = dioxus::desktop::Config::new()
        .with_window(
            dioxus::desktop::WindowBuilder::new()
                .with_title("FragglePacket")
                .with_inner_size(dioxus::desktop::LogicalSize::new(1280.0, 800.0))
                .with_min_inner_size(dioxus::desktop::LogicalSize::new(800.0, 600.0))
        )
        .with_custom_head(format!(
            r#"<style>{}</style>"#,
            theme::get_css()
        ));

    dioxus::LaunchBuilder::desktop()
        .with_cfg(cfg)
        .launch(app::App);
}
