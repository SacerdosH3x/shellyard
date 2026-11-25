//! Small custom-painted widgets shared by the sidebar and the home page.

use std::sync::Arc;

use eframe::egui::{self, text::LayoutJob, Align2, Color32, FontId, Galley, Pos2, Rect, Response, Sense, Stroke, Ui, Vec2};
use egui_phosphor::regular as icon;

use crate::model::{Host, HostKind};
use crate::theme;

pub fn kind_icon(kind: HostKind) -> &'static str {
    match kind {
        HostKind::Server => icon::HARD_DRIVES,
        HostKind::Database => icon::DATABASE,
        HostKind::LoadBalancer => icon::TREE_STRUCTURE,
        HostKind::Bastion => icon::SHIELD,
        HostKind::Windows => icon::DESKTOP,
    }
}

/// Lays out one line of text, cut with an ellipsis if wider than `max_w`.
pub fn elided(ui: &Ui, text: &str, font: FontId, color: Color32, max_w: f32) -> Arc<Galley> {
    let mut job = LayoutJob::simple_singleline(text.to_owned(), font, color);
    job.wrap = egui::text::TextWrapping {
        max_width: max_w.max(10.0),
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('…'),
    };
    ui.fonts(|f| f.layout_job(job))
}

pub fn icon_tile(ui: &Ui, rect: Rect, glyph: &str, fg: Color32, bg: Color32) {
    let p = ui.painter();
    p.rect_filled(rect, 6.0, bg);
    p.text(rect.center(), Align2::CENTER_CENTER, glyph, FontId::proportional(rect.height() * 0.55), fg);
}

/// Draws a small outlined badge whose right edge is at `right_center`; returns its rect.
pub fn badge(ui: &Ui, right_center: Pos2, text: &str) -> Rect {
    let g = ui.fonts(|f| f.layout_no_wrap(text.to_owned(), FontId::proportional(10.0), theme::MUTED));
    let size = g.size() + Vec2::new(10.0, 4.0);
    let rect = Rect::from_min_size(Pos2::new(right_center.x - size.x, right_center.y - size.y / 2.0), size);
    let p = ui.painter();
    p.rect_filled(rect, 4.0, theme::SURFACE);
    p.rect_stroke(rect, 4.0, Stroke::new(1.0_f32, theme::BORDER));
    p.galley(rect.min + Vec2::new(5.0, 2.0), g, theme::MUTED);
    rect
}

pub fn section_label(ui: &mut Ui, glyph: Option<&str>, text: &str) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 5.0;
        if let Some(g) = glyph {
            ui.label(egui::RichText::new(g).size(11.0).color(theme::ACCENT));
        }
        ui.label(egui::RichText::new(text.to_uppercase()).size(10.5).color(theme::FAINT).strong());
    });
    ui.add_space(2.0);
}

pub fn relative_time(unix: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(unix);
    let s = now.saturating_sub(unix);
    match s {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86_399 => format!("{} h ago", s / 3600),
        _ => format!("{} d ago", s / 86_400),
    }
}

/// A host card for the home page grid.
pub fn host_card(ui: &mut Ui, host: &Host, width: f32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 52.0), Sense::click());
    let fill = if resp.hovered() { theme::SURFACE_HOVER } else { theme::SURFACE };
    let stroke = if resp.hovered() { Color32::from_rgb(0x34, 0x3d, 0x4a) } else { theme::BORDER };
    ui.painter().rect_filled(rect, 7.0, fill);
    ui.painter().rect_stroke(rect, 7.0, Stroke::new(1.0_f32, stroke));

    let tile = Rect::from_min_size(rect.min + Vec2::new(12.0, 11.0), Vec2::splat(30.0));
    icon_tile(ui, tile, kind_icon(host.kind), theme::BLUE, theme::BLUE_BG);

    let b = badge(ui, Pos2::new(rect.right() - 12.0, rect.center().y), &host.protocol_badge());
    let text_x = tile.right() + 12.0;
    let max_w = b.left() - 10.0 - text_x;
    let name = elided(ui, &host.name, FontId::proportional(13.5), theme::TEXT, max_w);
    ui.painter().galley(Pos2::new(text_x, rect.top() + 9.0), name, theme::TEXT);

    let mut sub = host.target();
    if let Some(t) = host.last_connected {
        sub = format!("{sub} · {}", relative_time(t));
    }
    let sub = elided(ui, &sub, FontId::proportional(11.0), theme::FAINT, max_w);
    ui.painter().galley(Pos2::new(text_x, rect.top() + 28.0), sub, theme::FAINT);

    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A compact host row for the sidebar.
pub fn host_row(ui: &mut Ui, host: &Host, indent: f32) -> Response {
    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 36.0), Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, 6.0, theme::SURFACE_HOVER);
    }
    let tile = Rect::from_min_size(rect.min + Vec2::new(4.0 + indent, 6.0), Vec2::splat(24.0));
    icon_tile(ui, tile, kind_icon(host.kind), theme::BLUE, theme::BLUE_BG);

    let mut right = rect.right() - 6.0;
    if host.favorite {
        ui.painter().text(
            Pos2::new(right, rect.center().y),
            Align2::RIGHT_CENTER,
            egui_phosphor::regular::STAR,
            FontId::proportional(13.0),
            theme::ACCENT,
        );
    }
    right -= 20.0;
    let b = badge(ui, Pos2::new(right, rect.center().y), &host.protocol_badge());

    let text_x = tile.right() + 9.0;
    let max_w = b.left() - 6.0 - text_x;
    let name = elided(ui, &host.name, FontId::proportional(13.0), theme::TEXT, max_w);
    ui.painter().galley(Pos2::new(text_x, rect.top() + 3.0), name, theme::TEXT);
    let sub = elided(ui, &host.target(), FontId::proportional(10.5), theme::FAINT, max_w);
    ui.painter().galley(Pos2::new(text_x, rect.top() + 20.0), sub, theme::FAINT);

    resp
}

/// A folder header row with caret, colored icon, name and count.
pub fn folder_row(ui: &mut Ui, name: &str, path: &str, count: usize, open: bool, indent: f32) -> Response {
    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 28.0), Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, 6.0, theme::SURFACE_HOVER);
    }
    let y = rect.center().y;
    let mut x = rect.left() + 4.0 + indent;
    let caret = if open { icon::CARET_DOWN } else { icon::CARET_RIGHT };
    ui.painter().text(Pos2::new(x, y), Align2::LEFT_CENTER, caret, FontId::proportional(11.0), theme::MUTED);
    x += 16.0;
    ui.painter().text(
        Pos2::new(x, y),
        Align2::LEFT_CENTER,
        icon::FOLDER_SIMPLE,
        FontId::proportional(14.0),
        theme::folder_color(path),
    );
    x += 22.0;
    let count_rect = ui.painter().text(
        Pos2::new(rect.right() - 8.0, y),
        Align2::RIGHT_CENTER,
        count.to_string(),
        FontId::proportional(10.5),
        theme::FAINT,
    );
    let g = elided(ui, name, FontId::proportional(13.0), theme::TEXT, count_rect.left() - 8.0 - x);
    let h = g.size().y;
    ui.painter().galley(Pos2::new(x, y - h / 2.0), g, theme::TEXT);
    resp
}

/// A search box with an icon and an optional accent border.
pub fn search_box(ui: &mut Ui, text: &mut String, hint: &str, height: f32, accent: bool, id: egui::Id) -> Response {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());
    let has_focus = ui.memory(|m| m.has_focus(id));
    let stroke = if accent || has_focus {
        Stroke::new(if accent { 1.5_f32 } else { 1.0 }, theme::ACCENT)
    } else {
        Stroke::new(1.0_f32, theme::BORDER)
    };
    ui.painter().rect_filled(rect, 7.0, Color32::from_rgb(0x0f, 0x13, 0x18));
    ui.painter().rect_stroke(rect, 7.0, stroke);
    ui.painter().text(
        Pos2::new(rect.left() + 12.0, rect.center().y),
        Align2::LEFT_CENTER,
        icon::MAGNIFYING_GLASS,
        FontId::proportional(14.0),
        theme::MUTED,
    );
    let inner = Rect::from_min_max(Pos2::new(rect.left() + 32.0, rect.top()), Pos2::new(rect.right() - 8.0, rect.bottom()));
    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(inner).layout(egui::Layout::left_to_right(egui::Align::Center)));
    child.add(
        egui::TextEdit::singleline(text)
            .id(id)
            .hint_text(egui::RichText::new(hint).color(theme::FAINT))
            .frame(false)
            .desired_width(inner.width()),
    )
}

/// A plain icon button without a frame; brightens on hover.
pub fn icon_button(ui: &mut Ui, glyph: &str, tooltip: &str) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(24.0), Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, 5.0, theme::SURFACE_HOVER);
    }
    let color = if resp.hovered() { theme::TEXT } else { theme::MUTED };
    ui.painter().text(rect.center(), Align2::CENTER_CENTER, glyph, FontId::proportional(15.0), color);
    resp.on_hover_text(tooltip)
}

/// A chip-style button with icon and label (used for local terminals).
pub fn chip(ui: &mut Ui, glyph: &str, label: &str) -> Response {
    let g = ui.fonts(|f| f.layout_no_wrap(label.to_owned(), FontId::proportional(13.0), theme::TEXT));
    let size = Vec2::new(g.size().x + 44.0, 34.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let fill = if resp.hovered() { theme::SURFACE_HOVER } else { theme::SURFACE };
    ui.painter().rect_filled(rect, 7.0, fill);
    ui.painter().rect_stroke(rect, 7.0, Stroke::new(1.0_f32, theme::BORDER));
    ui.painter().text(
        Pos2::new(rect.left() + 14.0, rect.center().y),
        Align2::LEFT_CENTER,
        glyph,
        FontId::proportional(14.0),
        theme::ACCENT,
    );
    ui.painter().galley(Pos2::new(rect.left() + 32.0, rect.center().y - g.size().y / 2.0), g, theme::TEXT);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A primary (accent-filled) button.
pub fn primary_button(ui: &mut Ui, label: &str) -> Response {
    ui.add(
        egui::Button::new(egui::RichText::new(label).color(theme::ON_ACCENT).strong())
            .fill(theme::ACCENT)
            .stroke(Stroke::NONE)
            .min_size(Vec2::new(0.0, 30.0)),
    )
}
