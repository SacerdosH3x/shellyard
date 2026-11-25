//! Split panes inside a tab, tmux style: a tab holds a tree of splits whose
//! leaves are panes (a terminal or an RDP view). Dividers can be dragged, a
//! pane's title bar can be dropped on another pane to swap the two, and the
//! keyboard shortcuts follow tmux (prefix, then % " arrows o x z { } !).

use eframe::egui::{self, Color32, CursorIcon, FontId, Id, Pos2, Rect, Sense, Stroke, Ui, Vec2};

use super::Pane;
use crate::theme;

pub(super) type PaneId = u64;

/// How a split arranges its two halves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Dir {
    /// Side by side (tmux `%`).
    Right,
    /// One above the other (tmux `"`).
    Down,
}

/// A direction to move focus or a divider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Nav {
    Left,
    Right,
    Up,
    Down,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Layout {
    Leaf(PaneId),
    Split { dir: Dir, ratio: f32, a: Box<Layout>, b: Box<Layout> },
}

const GAP: f32 = 4.0;
const HEADER: f32 = 20.0;

impl Layout {
    /// Puts `new` next to `target` (after it), splitting `target`'s space.
    pub fn split(&mut self, target: PaneId, new: PaneId, dir: Dir) -> bool {
        match self {
            Layout::Leaf(id) if *id == target => {
                *self = Layout::Split { dir, ratio: 0.5, a: Box::new(Layout::Leaf(target)), b: Box::new(Layout::Leaf(new)) };
                true
            }
            Layout::Leaf(_) => false,
            Layout::Split { a, b, .. } => a.split(target, new, dir) || b.split(target, new, dir),
        }
    }

    /// Removes a pane; its sibling takes the space. False if `target` is the
    /// only pane (the caller closes the tab instead) or is not here.
    pub fn remove(&mut self, target: PaneId) -> bool {
        let Layout::Split { a, b, .. } = self else { return false };
        if **a == Layout::Leaf(target) {
            *self = (**b).clone();
            return true;
        }
        if **b == Layout::Leaf(target) {
            *self = (**a).clone();
            return true;
        }
        a.remove(target) || b.remove(target)
    }

    /// Panes in reading order (left to right, top to bottom).
    pub fn leaves(&self) -> Vec<PaneId> {
        match self {
            Layout::Leaf(id) => vec![*id],
            Layout::Split { a, b, .. } => {
                let mut v = a.leaves();
                v.extend(b.leaves());
                v
            }
        }
    }

    pub fn swap(&mut self, x: PaneId, y: PaneId) {
        match self {
            Layout::Leaf(id) if *id == x => *id = y,
            Layout::Leaf(id) if *id == y => *id = x,
            Layout::Leaf(_) => {}
            Layout::Split { a, b, .. } => {
                a.swap(x, y);
                b.swap(x, y);
            }
        }
    }

    fn halves(dir: Dir, ratio: f32, rect: Rect) -> (Rect, Rect, Rect) {
        match dir {
            Dir::Right => {
                let x = rect.left() + (rect.width() - GAP) * ratio;
                (
                    Rect::from_min_max(rect.min, Pos2::new(x, rect.bottom())),
                    Rect::from_min_max(Pos2::new(x, rect.top()), Pos2::new(x + GAP, rect.bottom())),
                    Rect::from_min_max(Pos2::new(x + GAP, rect.top()), rect.max),
                )
            }
            Dir::Down => {
                let y = rect.top() + (rect.height() - GAP) * ratio;
                (
                    Rect::from_min_max(rect.min, Pos2::new(rect.right(), y)),
                    Rect::from_min_max(Pos2::new(rect.left(), y), Pos2::new(rect.right(), y + GAP)),
                    Rect::from_min_max(Pos2::new(rect.left(), y + GAP), rect.max),
                )
            }
        }
    }

    /// Where each pane goes inside `rect`.
    pub fn rects(&self, rect: Rect) -> Vec<(PaneId, Rect)> {
        match self {
            Layout::Leaf(id) => vec![(*id, rect)],
            Layout::Split { dir, ratio, a, b } => {
                let (ra, _, rb) = Self::halves(*dir, *ratio, rect);
                let mut v = a.rects(ra);
                v.extend(b.rects(rb));
                v
            }
        }
    }

    /// The pane next to `from` in direction `nav`, as tmux picks it: the
    /// nearest one that overlaps on the other axis.
    pub fn neighbor(&self, rect: Rect, from: PaneId, nav: Nav) -> Option<PaneId> {
        let rects = self.rects(rect);
        let me = rects.iter().find(|(id, _)| *id == from)?.1;
        rects
            .iter()
            .filter(|(id, _)| *id != from)
            .filter(|(_, r)| match nav {
                Nav::Left => r.right() <= me.left() + 1.0 && overlaps(r.y_range(), me.y_range()),
                Nav::Right => r.left() >= me.right() - 1.0 && overlaps(r.y_range(), me.y_range()),
                Nav::Up => r.bottom() <= me.top() + 1.0 && overlaps(r.x_range(), me.x_range()),
                Nav::Down => r.top() >= me.bottom() - 1.0 && overlaps(r.x_range(), me.x_range()),
            })
            .min_by(|(_, a), (_, b)| a.center().distance(me.center()).total_cmp(&b.center().distance(me.center())))
            .map(|(id, _)| *id)
    }

    /// Moves the nearest divider around `target` that runs across `nav`'s
    /// axis by `step` (a fraction of that split).
    pub fn resize(&mut self, target: PaneId, nav: Nav, step: f32) -> bool {
        let want = if matches!(nav, Nav::Left | Nav::Right) { Dir::Right } else { Dir::Down };
        let delta = if matches!(nav, Nav::Left | Nav::Up) { -step } else { step };
        self.resize_inner(target, want, delta)
    }

    fn resize_inner(&mut self, target: PaneId, want: Dir, delta: f32) -> bool {
        let Layout::Split { dir, ratio, a, b } = self else { return false };
        let in_a = a.leaves().contains(&target);
        let in_b = !in_a && b.leaves().contains(&target);
        if !in_a && !in_b {
            return false;
        }
        // The deepest matching split wins, as in tmux.
        let deeper = if in_a { a.resize_inner(target, want, delta) } else { b.resize_inner(target, want, delta) };
        if deeper {
            return true;
        }
        if *dir == want {
            *ratio = (*ratio + delta).clamp(0.1, 0.9);
            return true;
        }
        false
    }
}

fn overlaps(a: egui::Rangef, b: egui::Rangef) -> bool {
    a.min < b.max - 1.0 && b.min < a.max - 1.0
}

/// A tab: one or more panes.
pub(super) struct Session {
    pub panes: Vec<Pane>,
    pub layout: Layout,
    pub focus: PaneId,
    /// Only the focused pane is shown (tmux `z`).
    pub zoom: bool,
    /// Set when focus moved, so the pane's view takes keyboard focus.
    pub focus_changed: bool,
}

impl Session {
    pub fn new(p: Pane) -> Self {
        let id = p.id;
        Self { panes: vec![p], layout: Layout::Leaf(id), focus: id, zoom: false, focus_changed: true }
    }

    pub fn focused(&self) -> &Pane {
        self.panes.iter().find(|p| p.id == self.focus).unwrap_or(&self.panes[0])
    }

    pub fn focused_mut(&mut self) -> &mut Pane {
        let i = self.panes.iter().position(|p| p.id == self.focus).unwrap_or(0);
        &mut self.panes[i]
    }

    pub fn pane_mut(&mut self, id: PaneId) -> Option<&mut Pane> {
        self.panes.iter_mut().find(|p| p.id == id)
    }

    /// The first pane's name, plus how many more there are.
    pub fn label(&self) -> String {
        let first = &self.panes[0].label;
        match self.panes.len() {
            1 => first.clone(),
            n => format!("{first} +{}", n - 1),
        }
    }

    pub fn glyph(&self) -> &'static str {
        self.focused().glyph
    }

    pub fn set_focus(&mut self, id: PaneId) {
        if self.panes.iter().any(|p| p.id == id) && id != self.focus {
            self.focus = id;
            self.focus_changed = true;
        }
    }

    pub fn add(&mut self, p: Pane, dir: Dir) {
        let id = p.id;
        if self.layout.split(self.focus, id, dir) {
            self.panes.push(p);
            self.zoom = false;
            self.set_focus(id);
        }
    }

    /// Removes a pane and returns it; `None` if it is the last one.
    pub fn take(&mut self, id: PaneId) -> Option<Pane> {
        if self.panes.len() < 2 || !self.layout.remove(id) {
            return None;
        }
        let i = self.panes.iter().position(|p| p.id == id)?;
        let p = self.panes.remove(i);
        if self.focus == id {
            let next = self.layout.leaves()[0];
            self.set_focus(next);
        }
        self.zoom = false;
        Some(p)
    }

    /// Focuses the next (or previous) pane in reading order.
    pub fn cycle(&mut self, forward: bool) {
        let order = self.layout.leaves();
        if let Some(i) = order.iter().position(|id| *id == self.focus) {
            let n = order.len();
            let j = if forward { (i + 1) % n } else { (i + n - 1) % n };
            self.set_focus(order[j]);
        }
    }

    /// Swaps the focused pane with the next (or previous) one; focus follows it.
    pub fn swap_with(&mut self, forward: bool) {
        let order = self.layout.leaves();
        if let Some(i) = order.iter().position(|id| *id == self.focus) {
            let n = order.len();
            let j = if forward { (i + 1) % n } else { (i + n - 1) % n };
            self.layout.swap(order[i], order[j]);
        }
    }
}

/// Draws a tab's panes. Returns the pane whose title bar was dropped on
/// another pane, as (dragged, target), for the caller to swap.
pub(super) fn show(ui: &mut Ui, s: &mut Session) -> Option<(PaneId, PaneId)> {
    let full = ui.available_rect_before_wrap();
    ui.allocate_rect(full, Sense::hover());
    if s.panes.len() == 1 || s.zoom {
        let id = s.focus;
        if let Some(p) = s.pane_mut(id) {
            let mut child = ui.new_child(egui::UiBuilder::new().max_rect(full));
            p.term.show(&mut child);
        }
        return None;
    }

    // Dividers first, so dragging one wins over the panes under it.
    drag_dividers(ui, &mut s.layout, full, Id::new("pane-split"));

    let rects = s.layout.rects(full);
    let pointer = ui.input(|i| i.pointer.interact_pos());
    let pressed = ui.input(|i| i.pointer.any_pressed());
    let mut dropped: Option<(PaneId, PaneId)> = None;
    let dragging: Option<PaneId> = ui.memory(|m| m.data.get_temp(Id::new("pane-drag")));
    for (id, rect) in &rects {
        let focused = *id == s.focus;
        let header = Rect::from_min_size(rect.min, Vec2::new(rect.width(), HEADER));
        let body = Rect::from_min_max(Pos2::new(rect.left(), rect.top() + HEADER), rect.max);
        if pressed && pointer.is_some_and(|p| rect.contains(p)) {
            s.set_focus(*id);
        }
        let Some(p) = s.panes.iter_mut().find(|p| p.id == *id) else { continue };

        // Title bar: shows which pane is which and can be dragged onto another pane.
        let resp = ui.interact(header, Id::new(("pane-header", *id)), Sense::click_and_drag()).on_hover_cursor(CursorIcon::Grab);
        let fill = if focused { theme::accent_soft() } else { theme::PANEL };
        ui.painter().rect_filled(header, 0.0, fill);
        let color = if focused { theme::ACCENT } else { theme::MUTED };
        let title = format!("{}  {}", p.glyph, p.label);
        let g = crate::widgets::elided(ui, &title, FontId::proportional(11.5), color, header.width() - 16.0);
        ui.painter().galley(header.left_center() + Vec2::new(8.0, -g.size().y / 2.0), g, color);
        if resp.drag_started() {
            ui.memory_mut(|m| m.data.insert_temp(Id::new("pane-drag"), *id));
        }

        let mut child = ui.new_child(egui::UiBuilder::new().max_rect(body));
        p.term.show(&mut child);
        if focused {
            ui.painter().rect_stroke(rect.shrink(0.5), 0.0, Stroke::new(1.0_f32, theme::ACCENT.gamma_multiply(0.6)));
        }
    }

    // A title bar being dragged: highlight the pane under the pointer, swap on release.
    if let Some(from) = dragging {
        let over = pointer.and_then(|p| rects.iter().find(|(_, r)| r.contains(p)).map(|(id, r)| (*id, *r)));
        if let Some((_, r)) = over.filter(|(to, _)| *to != from) {
            ui.painter().rect_filled(r, 0.0, Color32::from_rgba_unmultiplied(0x5b, 0xd6, 0x9b, 28));
            ui.painter().rect_stroke(r.shrink(1.0), 0.0, Stroke::new(2.0_f32, theme::ACCENT));
        }
        ui.ctx().set_cursor_icon(CursorIcon::Grabbing);
        if ui.input(|i| i.pointer.any_released()) {
            if let Some((to, _)) = over.filter(|(to, _)| *to != from) {
                dropped = Some((from, to));
            }
            ui.memory_mut(|m| m.data.remove::<PaneId>(Id::new("pane-drag")));
        }
    }
    dropped
}

fn drag_dividers(ui: &mut Ui, layout: &mut Layout, rect: Rect, id: Id) {
    let Layout::Split { dir, ratio, a, b } = layout else { return };
    let (ra, gap, rb) = Layout::halves(*dir, *ratio, rect);
    let resp = ui.interact(gap.expand(2.0), id, Sense::drag());
    let cursor = if *dir == Dir::Right { CursorIcon::ResizeHorizontal } else { CursorIcon::ResizeVertical };
    if resp.hovered() || resp.dragged() {
        ui.ctx().set_cursor_icon(cursor);
    }
    ui.painter().rect_filled(gap, 0.0, if resp.dragged() || resp.hovered() { theme::ACCENT.gamma_multiply(0.5) } else { theme::BORDER });
    if let (true, Some(p)) = (resp.dragged(), resp.interact_pointer_pos()) {
        *ratio = match dir {
            Dir::Right => (p.x - rect.left()) / rect.width(),
            Dir::Down => (p.y - rect.top()) / rect.height(),
        }
        .clamp(0.1, 0.9);
    }
    drag_dividers(ui, a, ra, id.with("a"));
    drag_dividers(ui, b, rb, id.with("b"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen() -> Rect {
        Rect::from_min_size(Pos2::ZERO, Vec2::new(1000.0, 600.0))
    }

    #[test]
    fn splitting_and_closing_keep_the_tree_tidy() {
        let mut l = Layout::Leaf(1);
        assert!(l.split(1, 2, Dir::Right));
        assert!(l.split(2, 3, Dir::Down));
        assert_eq!(l.leaves(), vec![1, 2, 3]);
        assert!(l.remove(2));
        assert_eq!(l, Layout::Split { dir: Dir::Right, ratio: 0.5, a: Box::new(Layout::Leaf(1)), b: Box::new(Layout::Leaf(3)) });
        assert!(l.remove(1));
        assert_eq!(l, Layout::Leaf(3));
        assert!(!l.remove(3), "the last pane cannot be removed");
    }

    #[test]
    fn focus_moves_like_tmux() {
        // 1 | 2
        //   | -
        //   | 3
        let mut l = Layout::Leaf(1);
        l.split(1, 2, Dir::Right);
        l.split(2, 3, Dir::Down);
        assert_eq!(l.neighbor(screen(), 1, Nav::Right), Some(2));
        assert_eq!(l.neighbor(screen(), 2, Nav::Down), Some(3));
        assert_eq!(l.neighbor(screen(), 3, Nav::Up), Some(2));
        assert_eq!(l.neighbor(screen(), 3, Nav::Left), Some(1));
        assert_eq!(l.neighbor(screen(), 1, Nav::Left), None);
        assert_eq!(l.neighbor(screen(), 2, Nav::Right), None);
    }

    #[test]
    fn rects_fill_the_space_without_overlap() {
        let mut l = Layout::Leaf(1);
        l.split(1, 2, Dir::Right);
        l.split(1, 3, Dir::Down);
        let rects = l.rects(screen());
        assert_eq!(rects.len(), 3);
        for (i, (_, a)) in rects.iter().enumerate() {
            for (_, b) in &rects[i + 1..] {
                assert!(a.intersect(*b).area() <= 0.0, "{a:?} overlaps {b:?}");
            }
        }
        let area: f32 = rects.iter().map(|(_, r)| r.area()).sum();
        assert!(area > screen().area() * 0.98);
    }

    #[test]
    fn swap_and_resize() {
        let mut l = Layout::Leaf(1);
        l.split(1, 2, Dir::Right);
        l.swap(1, 2);
        assert_eq!(l.leaves(), vec![2, 1]);
        assert!(l.resize(1, Nav::Left, 0.1));
        let Layout::Split { ratio, .. } = l else { panic!() };
        assert!((ratio - 0.4).abs() < 1e-6);
        assert!(!l.resize(1, Nav::Up, 0.1), "no vertical divider to move");
    }
}
