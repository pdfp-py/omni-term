//! Filas de lista: icono o punto, título, subtítulo y una zona derecha para acciones.

use eframe::egui::{self, Align2, Color32, CornerRadius, FontId, Pos2, Rect, Sense, Ui, Vec2};

use crate::ui::icons;
use crate::data::store::Connection;
use crate::ui::theme;

/// Lo que va a la izquierda del texto de una fila.
pub enum Leading {
    /// Icono de la fuente de iconos.
    Glyph(&'static str),
    /// Punto de color (estado).
    Dot(Color32),
}

/// Centro horizontal del icono o punto, y comienzo del texto, respecto al borde izquierdo de la fila.
const LEADING_X: f32 = 18.0;
const TEXT_X: f32 = 38.0;

/// Texto de una fila.
pub struct RowContent<'a> {
    pub leading: Leading,
    pub title: &'a str,
    pub subtitle: &'a str,
    /// El texto se acorta con «…» antes de esta coordenada x (el comienzo de los botones de la derecha).
    pub right_limit: f32,
}

/// Reserva una fila de ancho completo y le da fondo al pasar el ratón. Devuelve su rectángulo y su respuesta.
pub fn row_frame(ui: &mut Ui, height: f32, sense: Sense) -> (Rect, egui::Response) {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), sense);
    if response.hovered() {
        ui.painter().rect_filled(rect, CornerRadius::same(theme::radius::CONTROL), theme::surface());
    }
    (rect, response)
}

/// Dibuja el icono, el título y el subtítulo de una fila, centrados en vertical.
pub fn row_content(ui: &Ui, rect: Rect, content: RowContent<'_>) {
    let clip = Rect::from_min_max(rect.min, Pos2::new(content.right_limit, rect.max.y));
    let painter = ui.painter().with_clip_rect(clip);
    let text_x = rect.min.x + TEXT_X;
    match content.leading {
        Leading::Glyph(glyph) => {
            painter.text(Pos2::new(rect.min.x + LEADING_X, rect.center().y), Align2::CENTER_CENTER, glyph, FontId::proportional(theme::size::ICON_LG), theme::subtext());
        }
        Leading::Dot(color) => {
            painter.circle_filled(Pos2::new(rect.min.x + LEADING_X, rect.center().y), 5.0, color);
        }
    }
    let width = (content.right_limit - text_x).max(0.0);
    let title_font = FontId::new(theme::size::BODY, crate::ui::strong_family());
    let subtitle_font = FontId::new(theme::size::SMALL, egui::FontFamily::Proportional);
    let title = fit_text(&painter, content.title, &title_font, width);
    let subtitle = fit_text(&painter, content.subtitle, &subtitle_font, width);
    let heights = |text: &str, font: &FontId| painter.layout_no_wrap(text.to_string(), font.clone(), Color32::PLACEHOLDER).size().y;
    let (title_h, subtitle_h) = (heights(&title, &title_font), heights(&subtitle, &subtitle_font));
    let top = rect.center().y - (title_h + subtitle_h + 1.0) / 2.0;
    painter.text(Pos2::new(text_x, top), Align2::LEFT_TOP, title, title_font, theme::text());
    painter.text(Pos2::new(text_x, top + title_h + 1.0), Align2::LEFT_TOP, subtitle, subtitle_font, theme::subtext());
}

/// Icono que representa el tipo de una conexión: terminal, carpeta (archivos) o tres puntos (otros).
pub fn connection_glyph(connection: &Connection) -> &'static str {
    if connection.is_files() {
        icons::FOLDER
    } else if connection.is_adb() {
        icons::DOTS
    } else if connection.is_local() {
        icons::DESKTOP
    } else if connection.is_engine() {
        icons::CUBE
    } else {
        icons::TERMINAL
    }
}

/// Recorta `text` con «…» para que quepa en `width` píxeles.
pub fn fit_text(painter: &egui::Painter, text: &str, font: &FontId, width: f32) -> String {
    let measure = |t: &str| painter.layout_no_wrap(t.to_string(), font.clone(), Color32::PLACEHOLDER).size().x;
    if measure(text) <= width {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let (mut low, mut high) = (0, chars.len());
    while low < high {
        let mid = (low + high).div_ceil(2);
        let candidate: String = chars[..mid].iter().collect::<String>().trim_end().to_string() + "…";
        if measure(&candidate) <= width {
            low = mid
        } else {
            high = mid - 1
        }
    }
    chars[..low].iter().collect::<String>().trim_end().to_string() + "…"
}
