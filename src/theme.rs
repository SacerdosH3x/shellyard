use eframe::egui::{self, Color32, FontFamily, FontId, Rounding, Stroke, TextStyle};

pub const BG: Color32 = Color32::from_rgb(0x0d, 0x10, 0x15);
pub const PANEL: Color32 = Color32::from_rgb(0x11, 0x15, 0x1b);
pub const SURFACE: Color32 = Color32::from_rgb(0x16, 0x1b, 0x22);
pub const SURFACE_HOVER: Color32 = Color32::from_rgb(0x1d, 0x23, 0x2c);
pub const BORDER: Color32 = Color32::from_rgb(0x25, 0x2c, 0x36);
pub const TEXT: Color32 = Color32::from_rgb(0xe6, 0xe9, 0xee);
pub const MUTED: Color32 = Color32::from_rgb(0x8b, 0x94, 0xa3);
pub const FAINT: Color32 = Color32::from_rgb(0x5c, 0x66, 0x75);
pub const ACCENT: Color32 = Color32::from_rgb(0xc5, 0xf0, 0x35);
pub const ON_ACCENT: Color32 = Color32::from_rgb(0x12, 0x16, 0x06);
pub const BLUE: Color32 = Color32::from_rgb(0x6b, 0xa6, 0xf5);
pub const BLUE_BG: Color32 = Color32::from_rgb(0x18, 0x25, 0x37);
pub const DANGER: Color32 = Color32::from_rgb(0xf0, 0x6a, 0x6a);

pub const FOLDER_COLORS: [Color32; 6] = [
    Color32::from_rgb(0xf0, 0x6a, 0x6a),
    Color32::from_rgb(0xa7, 0x8b, 0xfa),
    Color32::from_rgb(0xf0, 0xa4, 0x50),
    Color32::from_rgb(0x6b, 0xa6, 0xf5),
    Color32::from_rgb(0x4f, 0xd1, 0xa5),
    Color32::from_rgb(0xf4, 0x7f, 0xc0),
];

pub fn accent_soft() -> Color32 {
    Color32::from_rgba_unmultiplied(0xc5, 0xf0, 0x35, 26)
}

pub fn folder_color(name: &str) -> Color32 {
    let top = name.split('/').next().unwrap_or(name);
    let h = top.bytes().fold(5381u32, |h, b| h.wrapping_mul(33) ^ b as u32);
    FOLDER_COLORS[h as usize % FOLDER_COLORS.len()]
}

pub fn install(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    ctx.set_fonts(fonts);

    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Heading, FontId::new(19.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(11.0, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
    ]
    .into();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    style.spacing.interact_size.y = 26.0;

    let v = &mut style.visuals;
    *v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.window_stroke = Stroke::new(1.0_f32, BORDER);
    v.window_rounding = Rounding::same(10.0);
    v.menu_rounding = Rounding::same(8.0);
    v.extreme_bg_color = Color32::from_rgb(0x0f, 0x13, 0x18);
    v.faint_bg_color = SURFACE;
    v.code_bg_color = SURFACE;
    v.hyperlink_color = ACCENT;
    v.selection.bg_fill = Color32::from_rgba_unmultiplied(0xc5, 0xf0, 0x35, 60);
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    v.text_cursor.stroke = Stroke::new(2.0_f32, ACCENT);

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = PANEL;
    w.noninteractive.weak_bg_fill = PANEL;
    w.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    w.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    w.noninteractive.rounding = Rounding::same(6.0);
    for (state, fill) in [
        (&mut w.inactive, SURFACE),
        (&mut w.hovered, SURFACE_HOVER),
        (&mut w.active, SURFACE_HOVER),
        (&mut w.open, SURFACE_HOVER),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.bg_stroke = Stroke::new(1.0_f32, BORDER);
        state.fg_stroke = Stroke::new(1.0_f32, TEXT);
        state.rounding = Rounding::same(6.0);
        state.expansion = 0.0;
    }
    w.inactive.fg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(0xc9, 0xcf, 0xd8));
    w.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(0x34, 0x3d, 0x4a));
    w.active.bg_stroke = Stroke::new(1.0_f32, ACCENT);

    ctx.set_style(style);
}
