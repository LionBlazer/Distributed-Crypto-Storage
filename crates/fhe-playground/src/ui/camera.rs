use eframe::egui;

#[derive(Clone, Copy, Debug)]
pub(super) struct Camera {
    pub center: egui::Vec2,
    pub zoom: f32,
}
impl Default for Camera {
    fn default() -> Self {
        Self {
            center: egui::Vec2::ZERO,
            zoom: 1.0,
        }
    }
}
impl Camera {
    pub fn world_to_screen(&self, canvas: egui::Rect, world: egui::Pos2) -> egui::Pos2 {
        canvas.center() + (world.to_vec2() - self.center) * self.zoom
    }
    pub fn screen_to_world(&self, canvas: egui::Rect, screen: egui::Pos2) -> egui::Pos2 {
        ((screen - canvas.center()) / self.zoom + self.center).to_pos2()
    }
    pub fn pan(&mut self, pixels: egui::Vec2) {
        self.center -= pixels / self.zoom;
    }
    pub fn zoom_at(&mut self, canvas: egui::Rect, screen: egui::Pos2, factor: f32) {
        let before = self.screen_to_world(canvas, screen);
        self.zoom = (self.zoom * factor).clamp(0.00001, 2.5);
        let after = self.screen_to_world(canvas, screen);
        self.center += before - after;
    }
    pub fn fit(&mut self, canvas: egui::Rect, bounds: egui::Rect) {
        self.center = bounds.center().to_vec2();
        self.zoom = ((canvas.width() - 50.0) / bounds.width().max(1.0))
            .min((canvas.height() - 50.0) / bounds.height().max(1.0))
            .clamp(0.00001, 1.3);
    }
    /// World lattice rendered through the same camera as the nodes.
    pub fn grid_points(&self, canvas: egui::Rect) -> Vec<egui::Pos2> {
        let stride = (8.0 / (28.0 * self.zoom)).ceil().max(1.0) as u32;
        let step = 28.0 * stride.next_power_of_two() as f32;
        let min = self.screen_to_world(canvas, canvas.min);
        let max = self.screen_to_world(canvas, canvas.max);
        let mut points = Vec::new();
        for x in (min.x / step).floor() as i32..=(max.x / step).ceil() as i32 {
            for y in (min.y / step).floor() as i32..=(max.y / step).ceil() as i32 {
                let point =
                    self.world_to_screen(canvas, egui::pos2(x as f32 * step, y as f32 * step));
                if canvas.contains(point) {
                    points.push(point);
                }
            }
        }
        points
    }
}
