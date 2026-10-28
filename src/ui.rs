pub mod cursor;
pub mod dialogs;
pub mod fonts;
pub mod icons;
pub mod kit;
pub mod palette;
pub mod theme;

mod appearance;
mod central;
mod closing;
mod commands;
mod connecting;
mod dialog_flow;
mod empty;
mod library;
mod secrets_flow;
mod sessions;
mod sidebar;
mod startup;
mod tabs;
mod toasts;
mod window;

pub use self::appearance::strong_family;
use self::appearance::{install_fonts, install_visuals};
use self::empty::EmptyAction;
use self::sidebar::{group_environment, PINNED_LABEL};
use self::tabs::{tunnel_line, Body, Tab};
use self::toasts::{Cleanup, Toast, Undo};

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use eframe::egui::{
    self, Align2, Button, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Frame, Margin,
    Key, Modifiers, Panel, Pos2, Rect, RichText, Sense, Stroke, TextStyle, Vec2, ViewportCommand,
};
use zeroize::Zeroizing;

use crate::containers::view::{self, ContainersView};
use self::cursor::HandExt;
use crate::containers::docker;
use self::dialogs::{CloseAction, CloseConfirm, ConnForm, Dialog, ErrorInfo, Outcome, PaneTarget, Pending, Purpose, Retry, SecretPrompt, SnippetForm, TestState, UnlockPrompt, VarsPrompt};
use crate::terminal::layout::{Dir, Tree};
use crate::files::explorer::Explorer;
use crate::connect::known_hosts;
use self::palette::{Command, Palette, Target};
use crate::terminal::pane::{self, bold_family, Pane, PaneRequest, PADDING};
use crate::data::settings::{CursorChoice, Settings, StartupChoice, ThemeChoice, DEFAULT_FONT_SIZE, MAX_FONT_SIZE, MIN_FONT_SIZE};
use crate::data::secrets::{account_for, KeyringStore, MasterKeyStore, MigrateFrom, SecretError, SecretKind, SecretStore, Secrets};
use crate::connect::ssh::{self, Credentials, JumpHost, TunnelState, Tunnels, UiEvent};
use crate::data::store::{self, Auth, Connection, Forward, Protocol, SavedTab, Snippet, Store, TabKind};
use crate::connect::telnet;
use crate::terminal::term::{self, Session, TermOptions};

const SIDEBAR_WIDTH: f32 = 240.0;
const SIDEBAR_MIN: f32 = 200.0;
const SIDEBAR_MAX: f32 = 360.0;
/// Grupos con encabezado a partir de este número de conexiones.
const GROUP_THRESHOLD: usize = 5;
/// Ancho mínimo de una pestaña antes de que la tira empiece a desplazarse.
const MIN_TAB_WIDTH: f32 = 110.0;
/// Por debajo de este ancho de ventana la barra lateral se reduce a una tira de iconos.
const NARROW_WINDOW: f32 = 760.0;
const STRIP_WIDTH: f32 = 54.0;
const TAB_BAR_HEIGHT: f32 = 40.0;

const TAB_HEIGHT: f32 = 34.0;
const ROW_HEIGHT: f32 = 46.0;

/// Estado de las sesiones de una conexión, para el punto de la barra lateral.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LinkState {
    Closed,
    Open,
    Lost,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SidebarView {
    Connections,
    Snippets,
}

/// Separación entre paneles divididos; también aloja la barra de desplazamiento.
const SPLIT_GAP: f32 = 16.0;

pub struct App {
    tabs: Vec<Tab>,
    active: usize,
    debug_keys: bool,
    window_title: String,
    next_tab_id: u64,
    settings: Settings,
    window_saved: (u32, u32),
    window_saved_at: std::time::Instant,
    window_maximized: bool,
    window_pos: (i32, i32),
    window_restored: bool,
    window_boot: std::time::Instant,
    grid: (usize, usize),
    ctx: egui::Context,
    runtime: tokio::runtime::Runtime,
    store: Arc<Mutex<Store>>,
    secrets: Secrets,
    connections: Vec<Connection>,
    forwards: HashMap<i64, Vec<Forward>>,
    snippets: Vec<Snippet>,
    sidebar_view: SidebarView,
    /// Búsqueda de la barra lateral; filtra conexiones o snippets según la vista.
    sidebar_query: String,
    sidebar_collapsed: bool,
    /// Pestaña que se está renombrando: índice, texto y si falta darle el foco.
    renaming: Option<(usize, String, bool)>,
    palette: Option<Palette>,
    close_confirmed: bool,
    known_hosts: dialogs::KnownHostsView,
    /// Hosts de `~/.ssh/config` que aún no están guardados.
    ssh_config_hosts: usize,
    loaded_font: Option<String>,
    /// Ids de conexión, de la usada más recientemente a la más antigua.
    recent: Vec<(i64, u64)>,
    pinned: Vec<i64>,
    /// El foco está en la lista del sidebar (flechas, Enter, F2, Supr).
    sidebar_nav: bool,
    nav_index: usize,
    sidebar_rect: Rect,
    sidebar_epoch: u32,
    plus_selected: usize,
    open_plus_menu: bool,
    /// Última pestaña a la que se desplazó la tira de pestañas.
    tab_strip_seen: u64,
    /// Shells de contenedor por id de pestaña: su motor y el nombre del contenedor, para reconectar.
    container_shells: HashMap<u64, (docker::Endpoint, String)>,
    /// La barra de menú oculta se muestra de paso (tras pulsar Alt).
    menu_peek: bool,
    /// Alt pulsado: `true` si ya se pulsó otra tecla mientras tanto.
    alt_state: Option<bool>,
    sidebar_width: f32,
    focus_search: bool,
    /// Grupos de entorno plegados (en minúsculas).
    collapsed_groups: HashSet<String>,
    events_tx: Sender<UiEvent>,
    events_rx: Receiver<UiEvent>,
    pending_ui: VecDeque<UiEvent>,
    session_secrets: HashMap<(i64, SecretKind), Zeroizing<String>>,
    save_queue: VecDeque<(String, Zeroizing<String>)>,
    open_queue: VecDeque<SavedTab>,
    /// Hay que preguntar si se restaura la sesión anterior antes de abrir nada.
    restore_prompt: bool,
    /// Migración de secretos entre almacenes que se hace en este arranque.
    pending_migration: Option<MigrateFrom>,
    /// Clave maestra usada como origen o destino de una migración cuando el almacén activo es el llavero.
    migration_master: Option<Arc<MasterKeyStore>>,
    /// Si el llavero del sistema funciona; se sondea una sola vez cuando hace falta.
    keyring_probe: Option<bool>,
    restore_active: Option<usize>,
    dialog: Option<Dialog>,
    /// Diálogo apartado mientras otro (huella, 2FA) pasa por delante.
    suspended: Option<Dialog>,
    saved_layout: (Vec<SavedTab>, usize),
    toasts: Vec<Toast>,
    next_toast: u64,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, debug_keys: bool) -> anyhow::Result<Self> {
        install_visuals(&cc.egui_ctx);

        let mut startup_notice: Option<String> = None;
        let store = match Store::default_path().and_then(|path| Store::open(&path)) {
            Ok(store) => store,
            Err(error) => {
                startup_notice = Some(format!("Sin base de datos persistente: {error:#}"));
                Store::open_in_memory()?
            }
        };
        let (layout, active) = store.load_layout().unwrap_or_default();
        let connections = store.list_connections().unwrap_or_default();
        let forwards = store.all_forwards().unwrap_or_default();
        let snippets = store.list_snippets().unwrap_or_default();
        let store = Arc::new(Mutex::new(store));
        let store_meta_flag = matches!(store.lock().unwrap().meta("window_maximized"), Ok(Some(v)) if v == b"1");
        let secrets = Secrets::select(store.clone());
        let pending_migration = Secrets::pending_migration(&store.lock().unwrap());
        let keyring_probe = match (&secrets, Secrets::is_master_forced(&store.lock().unwrap())) {
            (Secrets::Keyring(_), _) => Some(true),
            (Secrets::Master(_), false) => Some(false),
            (Secrets::Master(_), true) => None,
        };
        let recent: Vec<(i64, u64)> = match store.lock().unwrap().meta("recent_connections") {
            Ok(Some(bytes)) => parse_recent(&String::from_utf8_lossy(&bytes)),
            _ => Vec::new(),
        };
        let pinned: Vec<i64> = match store.lock().unwrap().meta("pinned_connections") {
            Ok(Some(bytes)) => String::from_utf8_lossy(&bytes).split(',').filter_map(|id| id.trim().parse().ok()).collect(),
            _ => Vec::new(),
        };
        let settings = Settings::load(&store.lock().unwrap());
        let font_error = install_fonts(&cc.egui_ctx, settings.font_family.as_deref());
        theme::set_accent(settings.accent.index());
        theme::set_compact(settings.compact);
        theme::set_bold_bright(settings.bold_bright);
        theme::set_ansi_scheme(settings.ansi.index());
        let light = match settings.theme {
            ThemeChoice::Light => true,
            ThemeChoice::Dark => false,
            ThemeChoice::System => cc.egui_ctx.system_theme() == Some(egui::Theme::Light),
        };
        theme::set_light(light);
        install_visuals(&cc.egui_ctx);
        let sidebar_view = match store.lock().unwrap().meta("sidebar_view") {
            Ok(Some(value)) if value == b"snippets" => SidebarView::Snippets,
            _ => SidebarView::Connections,
        };
        let (sidebar_collapsed, sidebar_width, collapsed_groups) = {
            let store = store.lock().unwrap();
            let collapsed = matches!(store.meta("sidebar_collapsed"), Ok(Some(v)) if v == b"1");
            let width = match store.meta("sidebar_width") {
                Ok(Some(v)) => String::from_utf8_lossy(&v).parse::<f32>().unwrap_or(SIDEBAR_WIDTH),
                _ => SIDEBAR_WIDTH,
            };
            let groups = match store.meta("collapsed_groups") {
                Ok(Some(v)) => String::from_utf8_lossy(&v).lines().filter(|l| !l.is_empty()).map(str::to_string).collect(),
                _ => HashSet::new(),
            };
            (collapsed, width.clamp(SIDEBAR_MIN, SIDEBAR_MAX), groups)
        };
        cc.egui_ctx.options_mut(|options| options.zoom_with_keyboard = false);
        let (events_tx, events_rx) = mpsc::channel();

        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;

        let mut open_queue: VecDeque<SavedTab> = layout.into();
        let has_session = open_queue.iter().any(|s| !matches!(s.kind, TabKind::Local));
        let restore_prompt = has_session && settings.on_start == StartupChoice::Ask && std::env::var_os(RESTARTED_ENV).is_none();
        if has_session && settings.on_start == StartupChoice::Fresh {
            open_queue.clear();
        }
        let mut app = Self {
            tabs: Vec::new(),
            active: 0,
            debug_keys,
            window_title: String::new(),
            next_tab_id: 0,
            settings,
            window_saved: (0, 0),
            window_saved_at: std::time::Instant::now(),
            window_maximized: matches!(store_meta_flag, true),
            window_pos: (i32::MIN, i32::MIN),
            window_restored: false,
            window_boot: std::time::Instant::now(),
            grid: (80, 24),
            ctx: cc.egui_ctx.clone(),
            runtime,
            store,
            secrets,
            connections,
            forwards,
            snippets,
            sidebar_view,
            sidebar_query: String::new(),
            sidebar_collapsed,
            renaming: None,
            palette: None,
            close_confirmed: false,
            known_hosts: Default::default(),
            ssh_config_hosts: 0,
            loaded_font: None,
            recent,
            pinned,
            sidebar_nav: false,
            nav_index: 0,
            sidebar_rect: Rect::NOTHING,
            sidebar_epoch: 0,
            plus_selected: 0,
            open_plus_menu: false,
            tab_strip_seen: 0,
            container_shells: HashMap::new(),
            menu_peek: false,
            alt_state: None,
            sidebar_width,
            focus_search: false,
            collapsed_groups,
            events_tx,
            events_rx,
            pending_ui: VecDeque::new(),
            session_secrets: HashMap::new(),
            save_queue: VecDeque::new(),
            open_queue,
            restore_prompt,
            pending_migration,
            migration_master: None,
            keyring_probe,
            restore_active: Some(active),
            dialog: None,
            suspended: None,
            saved_layout: (Vec::new(), 0),
            toasts: Vec::new(),
            next_toast: 0,
        };
        app.ssh_config_hosts = pending_ssh_config_hosts(&app.connections);
        app.loaded_font = app.settings.font_family.clone();
        if let Some(problem) = font_error {
            app.settings.font_family = None;
            app.loaded_font = None;
            app.notify(problem);
        }
        if let Some(notice) = startup_notice {
            app.notify(notice);
        }
        Ok(app)
    }

    fn wake(&self) -> Arc<dyn Fn() + Send + Sync> {
        let ctx = self.ctx.clone();
        Arc::new(move || ctx.request_repaint())
    }

}

/// Estado vacío de una lista: título, explicación y una acción principal (y otra opcional).
fn empty_state(ui: &mut egui::Ui, title: &str, body: &str, primary: &str, secondary: Option<&str>) -> (bool, bool) {
    ui.add_space(theme::space::GROUP);
    ui.label(RichText::new(title).font(FontId::new(theme::size::HEADING, strong_family())).color(theme::text()));
    ui.add_space(theme::space::XXS);
    ui.label(RichText::new(body).small().color(theme::subtext()));
    ui.add_space(theme::space::XL);
    let width = ui.available_width();
    let create = crate::ui::kit::button_with(ui, Button::new(primary).min_size(Vec2::new(width, 32.0)), crate::ui::kit::Variant::Primary).clicked();
    let mut other = false;
    if let Some(label) = secondary {
        ui.add_space(theme::space::XS);
        let button = Button::new(RichText::new(label).color(theme::text())).min_size(Vec2::new(width, 32.0));
        other = crate::ui::kit::button_with(ui, button, crate::ui::kit::Variant::Secondary).clicked();
    }
    (create, other)
}

/// Cuántos hosts de `~/.ssh/config` aún no están guardados.
fn pending_ssh_config_hosts(saved: &[Connection]) -> usize {
    let path = std::env::home_dir().unwrap_or_default().join(".ssh").join("config");
    let Ok(text) = std::fs::read_to_string(path) else { return 0 };
    let user = std::env::var("USER").unwrap_or_default();
    crate::connect::sshconfig::parse(&text, &user).iter().filter(|h| !saved.iter().any(|c| c.name == h.connection.name)).count()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `id:segundos,id:segundos…`; también acepta el formato antiguo, solo ids.
fn parse_recent(text: &str) -> Vec<(i64, u64)> {
    text.split(',')
        .filter_map(|part| {
            let mut pieces = part.trim().splitn(2, ':');
            let id = pieces.next()?.parse().ok()?;
            Some((id, pieces.next().and_then(|t| t.parse().ok()).unwrap_or(0)))
        })
        .collect()
}

/// «ahora», «hace 5 min», «hace 3 h», «ayer», «hace 4 d»; vacío si no se sabe cuándo fue.
fn relative_time(then: u64, now: u64) -> String {
    if then == 0 || then > now {
        return String::new();
    }
    let seconds = now - then;
    match seconds {
        0..=59 => "ahora".to_string(),
        60..=3599 => format!("hace {} min", seconds / 60),
        3600..=86_399 => format!("hace {} h", seconds / 3600),
        86_400..=172_799 => "ayer".to_string(),
        _ => format!("hace {} d", seconds / 86_400),
    }
}

fn ctx_width(ctx: &egui::Context) -> f32 {
    ctx.content_rect().width()
}

/// Hasta que pasa este tiempo desde el arranque no se abren pestañas remotas restauradas.
fn clipboard_event() -> egui::Event {
    egui::Event::Paste(arboard::Clipboard::new().ok().and_then(|mut c| c.get_text().ok()).unwrap_or_default())
}

/// Variable que marca un reinicio pedido por la propia app: la sesión se restaura sin preguntar.
const RESTARTED_ENV: &str = "OMNITERM_RESTARTED";

const RESTORE_PROMPT_DELAY: Duration = Duration::from_millis(1000);

impl eframe::App for App {
    /// Con los atajos de portapapeles de eframe apagados (para que Ctrl+C/V lleguen a la terminal),
    /// los campos de texto los reciben aquí.
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        if !ctx.text_edit_focused() {
            return;
        }
        let mut extra = Vec::new();
        for event in &raw_input.events {
            let egui::Event::Key { key, pressed: true, modifiers, .. } = event else { continue };
            match key {
                Key::V if modifiers.command => extra.push(clipboard_event()),
                Key::Insert if modifiers.shift && !modifiers.command => extra.push(clipboard_event()),
                Key::C | Key::Insert if modifiers.command && !modifiers.shift => extra.push(egui::Event::Copy),
                Key::X if modifiers.command => extra.push(egui::Event::Cut),
                Key::Delete if modifiers.shift && !modifiers.command => extra.push(egui::Event::Cut),
                _ => {}
            }
        }
        extra.retain(|e| !matches!(e, egui::Event::Paste(text) if text.is_empty()));
        raw_input.events.extend(extra);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.sync_theme(&ctx);
        self.watch_activity(&ctx);
        self.restore_window_position(&ctx);
        self.remember_window_size(&ctx);

        self.global_shortcuts(&ctx);
        self.track_alt(&ctx);
        self.window_frame(&ctx);
        let (menu_command, menu_connection) = self.menu_bar(ui);
        if menu_command.is_some() || menu_connection.is_some() {
            self.menu_peek = false;
        }
        if let Some(command) = menu_command {
            if command == Command::Palette {
                self.palette = Some(Palette::default());
            } else {
                self.run_command(command);
            }
        }
        if let Some(connection) = menu_connection {
            self.begin_open(connection, None, Purpose::Terminal);
        }
        self.sidebar(ui);

        self.tab_strip(ui);

        self.central_area(ui, &ctx);

        if let Some(mut palette) = self.palette.take() {
            let items = self.palette_items();
            match palette.show(&ctx, &items) {
                palette::Outcome::Open => self.palette = Some(palette),
                palette::Outcome::Close => {}
                palette::Outcome::Run(index) => {
                    if let Some(item) = items.into_iter().nth(index) {
                        self.run_palette(item.target);
                    }
                }
            }
        }
        self.handle_dialog(&ctx);
        self.toasts_ui(&ctx);
        self.persist_layout();
    }
}
