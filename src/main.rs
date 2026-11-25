mod app;
mod askpass;
mod model;
mod rdp;
mod rdp_view;
mod store;
mod terminal;
mod theme;
mod vault;
mod widgets;

use eframe::egui;

fn main() -> eframe::Result<()> {
    // Started by OpenSSH as SSH_ASKPASS: answer and exit, no window.
    #[cfg(unix)]
    if let Some(code) = askpass::run_if_requested() {
        std::process::exit(code);
    }
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1320.0, 840.0])
        .with_min_inner_size([860.0, 520.0])
        .with_title("Shellyard")
        // Wayland app id / X11 class: matches packaging/linux/shellyard.desktop.
        .with_app_id("shellyard");
    if cfg!(target_os = "macos") {
        // Draw our own top bar under the traffic-light buttons.
        viewport = viewport.with_fullsize_content_view(true).with_titlebar_shown(false).with_title_shown(false);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native("Shellyard", options, Box::new(|cc| Ok(Box::new(app::App::new(cc)))))
}
