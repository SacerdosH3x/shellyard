mod app;
mod model;
mod store;
mod terminal;
mod theme;
mod vault;
mod widgets;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1320.0, 840.0])
        .with_min_inner_size([860.0, 520.0])
        .with_title("Shellyard");
    if cfg!(target_os = "macos") {
        // Draw our own top bar under the traffic-light buttons.
        viewport = viewport.with_fullsize_content_view(true).with_titlebar_shown(false).with_title_shown(false);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native("Shellyard", options, Box::new(|cc| Ok(Box::new(app::App::new(cc)))))
}
