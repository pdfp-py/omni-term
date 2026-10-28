//! Pestaña «Contenedores»: lista de Docker o Podman con iniciar, detener, reiniciar y abrir un terminal.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Align, FontId, Layout, Rect, RichText, Sense, Ui, UiBuilder, Vec2};
use tokio::runtime::Handle;

use crate::ui::cursor::HandExt;
use crate::connect::ssh::SshLink;
use crate::containers::docker::{self, Action, Client, Container, Endpoint, Via};
use crate::ui::theme;
use crate::ui::kit::IconButton;

/// Cada cuánto se refresca la lista mientras la pestaña está a la vista.
const REFRESH_EVERY: Duration = Duration::from_secs(3);
/// Si la pestaña no se dibuja durante este tiempo, se deja de consultar al motor.
const STALE_AFTER: Duration = Duration::from_secs(6);
const ROW_HEIGHT: f32 = 58.0;

#[derive(Default)]
struct Snapshot {
    loaded: bool,
    containers: Vec<Container>,
    error: Option<String>,
}

/// De dónde salen los motores de la pestaña.
#[derive(Clone)]
pub enum Source {
    /// Los que se detecten en este equipo.
    Here,
    /// Un socket concreto de este equipo (perfil con socket fijado).
    Socket(String),
    /// Un servidor por SSH; sin socket, se detectan al conectar.
    Remote { link: Arc<SshLink>, socket: Option<String> },
}

/// Lo que la vista le pide a la aplicación.
pub enum Request {
    Terminal(Endpoint, Container),
    /// Detener y reiniciar piden confirmación.
    Confirm(Endpoint, Container, Action),
}

pub struct ContainersView {
    title: String,
    source: Source,
    endpoints: Arc<Mutex<Vec<Endpoint>>>,
    /// Buscando motores (en un servidor, conectando por SSH).
    detecting: Arc<AtomicBool>,
    redetect: Arc<AtomicBool>,
    selected: usize,
    current: Arc<Mutex<Option<Endpoint>>>,
    snapshot: Arc<Mutex<Snapshot>>,
    last_seen: Arc<Mutex<Instant>>,
    refresh: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    busy: Arc<Mutex<Vec<String>>>,
    messages: Arc<Mutex<Vec<String>>>,
    runtime: Handle,
    wake: Arc<dyn Fn() + Send + Sync>,
    search: String,
    show_stopped: bool,
}

impl Drop for ContainersView {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl ContainersView {
    /// `title` distingue la pestaña de un perfil («Contenedores · prod»); la de este equipo es «Contenedores».
    pub fn new(runtime: Handle, wake: Arc<dyn Fn() + Send + Sync>, source: Source, title: String) -> Self {
        let view = Self {
            title,
            source,
            current: Arc::new(Mutex::new(None)),
            endpoints: Arc::new(Mutex::new(Vec::new())),
            detecting: Arc::new(AtomicBool::new(true)),
            redetect: Arc::new(AtomicBool::new(true)),
            selected: 0,
            snapshot: Arc::new(Mutex::new(Snapshot::default())),
            last_seen: Arc::new(Mutex::new(Instant::now())),
            refresh: Arc::new(AtomicBool::new(true)),
            stop: Arc::new(AtomicBool::new(false)),
            busy: Arc::new(Mutex::new(Vec::new())),
            messages: Arc::new(Mutex::new(Vec::new())),
            runtime,
            wake,
            search: String::new(),
            show_stopped: true,
        };
        view.start_polling();
        view
    }

    pub fn label(&self) -> String {
        self.title.clone()
    }

    /// El motor elegido ahora, para abrir un shell que reconecta.
    pub fn current_endpoint(&self) -> Option<Endpoint> {
        self.current.lock().unwrap().clone()
    }

    fn link(&self) -> Option<&Arc<SshLink>> {
        match &self.source {
            Source::Remote { link, .. } => Some(link),
            _ => None,
        }
    }

    /// Vuelve a conectar con el servidor y a buscar sus motores.
    pub fn reconnect(&mut self) {
        if let Some(link) = self.link() {
            link.reconnect();
        }
        *self.snapshot.lock().unwrap() = Snapshot::default();
        self.redetect.store(true, Ordering::SeqCst);
    }

    /// Avisos de acciones terminadas (o fallidas) para mostrarlos como notificación.
    pub fn take_messages(&self) -> Vec<String> {
        std::mem::take(&mut *self.messages.lock().unwrap())
    }

    fn start_polling(&self) {
        let (current, snapshot, last_seen, refresh, stop, wake) =
            (self.current.clone(), self.snapshot.clone(), self.last_seen.clone(), self.refresh.clone(), self.stop.clone(), self.wake.clone());
        let (source, endpoints, detecting, redetect) = (self.source.clone(), self.endpoints.clone(), self.detecting.clone(), self.redetect.clone());
        self.runtime.spawn(async move {
            let mut last_fetch: Option<Instant> = None;
            while !stop.load(Ordering::SeqCst) {
                if redetect.swap(false, Ordering::SeqCst) {
                    detecting.store(true, Ordering::SeqCst);
                    wake();
                    let found = match &source {
                        Source::Here => Ok(docker::detect_endpoints()),
                        Source::Socket(socket) => Ok(vec![Endpoint::fixed(socket, Via::Local)]),
                        Source::Remote { link, socket: Some(socket) } => link.session().await.map(|_| vec![Endpoint::fixed(socket, Via::Ssh(link.clone()))]),
                        Source::Remote { link, socket: None } => docker::detect_remote(link).await,
                    };
                    match found {
                        Ok(found) => {
                            *current.lock().unwrap() = found.first().cloned();
                            *endpoints.lock().unwrap() = found;
                        }
                        Err(error) => {
                            endpoints.lock().unwrap().clear();
                            *current.lock().unwrap() = None;
                            let mut snapshot = snapshot.lock().unwrap();
                            snapshot.loaded = true;
                            snapshot.error = Some(format!("{error:#}"));
                        }
                    }
                    detecting.store(false, Ordering::SeqCst);
                    last_fetch = None;
                    wake();
                }
                let forced = refresh.swap(false, Ordering::SeqCst);
                let visible = last_seen.lock().unwrap().elapsed() < STALE_AFTER;
                let due = last_fetch.is_none_or(|t| t.elapsed() >= REFRESH_EVERY);
                if forced || (visible && due) {
                    let endpoint = current.lock().unwrap().clone();
                    if let Some(endpoint) = endpoint {
                        let result = Client::new(endpoint.clone()).list().await;
                        // Si se cambió de motor mientras tanto, el resultado ya no vale.
                        if current.lock().unwrap().as_ref() == Some(&endpoint) {
                            let mut snapshot = snapshot.lock().unwrap();
                            snapshot.loaded = true;
                            match result {
                                Ok(list) => {
                                    snapshot.containers = list;
                                    snapshot.error = None;
                                }
                                Err(error) => snapshot.error = Some(format!("{error:#}")),
                            }
                        }
                        last_fetch = Some(Instant::now());
                        wake();
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }

    /// Ejecuta una acción en segundo plano y avisa del resultado.
    pub fn act(&self, endpoint: Endpoint, container: &Container, action: Action) {
        let (id, name) = (container.id.clone(), container.name.clone());
        self.busy.lock().unwrap().push(id.clone());
        let (busy, messages, refresh, wake) = (self.busy.clone(), self.messages.clone(), self.refresh.clone(), self.wake.clone());
        self.runtime.spawn(async move {
            let result = Client::new(endpoint).act(&id, action).await;
            let message = match (&result, action) {
                (Ok(()), Action::Start) => format!("«{name}» iniciado"),
                (Ok(()), Action::Stop) => format!("«{name}» detenido"),
                (Ok(()), Action::Restart) => format!("«{name}» reiniciado"),
                (Err(error), _) => format!("No se pudo con «{name}»: {error}"),
            };
            busy.lock().unwrap().retain(|b| *b != id);
            messages.lock().unwrap().push(message);
            refresh.store(true, Ordering::SeqCst);
            wake();
        });
    }

    fn select(&mut self, index: usize) {
        self.selected = index;
        *self.current.lock().unwrap() = self.endpoints.lock().unwrap().get(index).cloned();
        *self.snapshot.lock().unwrap() = Snapshot::default();
        self.refresh.store(true, Ordering::SeqCst);
    }

    fn redetect(&mut self) {
        self.selected = 0;
        *self.snapshot.lock().unwrap() = Snapshot::default();
        self.redetect.store(true, Ordering::SeqCst);
    }

    pub fn show(&mut self, ui: &mut Ui, area: Rect) -> Option<Request> {
        *self.last_seen.lock().unwrap() = Instant::now();
        let mut request = None;
        let mut child = ui.new_child(UiBuilder::new().max_rect(area).layout(Layout::top_down(Align::Min)));
        let ui = &mut child;
        ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);

        let endpoints = self.endpoints.lock().unwrap().clone();
        self.header(ui, &endpoints);
        ui.add_space(theme::space::XS);

        let (loaded, error, containers) = {
            let snapshot = self.snapshot.lock().unwrap();
            (snapshot.loaded, snapshot.error.clone(), snapshot.containers.clone())
        };
        if let Some(error) = error {
            ui.add_space(theme::space::L);
            ui.label(RichText::new(error).color(theme::red()));
            // Con la sesión SSH caída hay que reconectar; si no, basta con volver a intentarlo.
            if self.link().is_some_and(|link| link.is_lost()) {
                if ui.button("Reconectar").hand().clicked() {
                    self.reconnect();
                }
            } else if ui.button("Reintentar").hand().clicked() {
                if endpoints.is_empty() {
                    self.redetect();
                } else {
                    self.refresh.store(true, Ordering::SeqCst);
                }
            }
            return None;
        }
        if self.detecting.load(Ordering::SeqCst) {
            ui.add_space(theme::space::L);
            let text = match self.link() {
                Some(link) => format!("Conectando con {}…", link.name()),
                None => "Buscando motores…".to_string(),
            };
            ui.label(RichText::new(text).color(theme::subtext()));
            return None;
        }
        if endpoints.is_empty() {
            self.empty(ui);
            return None;
        }
        if !loaded {
            ui.add_space(theme::space::L);
            ui.label(RichText::new("Cargando contenedores…").color(theme::subtext()));
            return None;
        }

        let needle = self.search.trim().to_lowercase();
        let mut shown: Vec<&Container> = containers
            .iter()
            .filter(|c| self.show_stopped || c.is_running())
            .filter(|c| needle.is_empty() || c.name.to_lowercase().contains(&needle) || c.image.to_lowercase().contains(&needle))
            .collect();
        shown.sort_by(|a, b| b.is_running().cmp(&a.is_running()).then_with(|| a.name.cmp(&b.name)));

        if shown.is_empty() {
            ui.add_space(theme::space::L);
            let text = if containers.is_empty() { "No hay contenedores." } else { "Ningún contenedor coincide." };
            ui.label(RichText::new(text).color(theme::subtext()));
            return None;
        }
        let endpoint = endpoints[self.selected.min(endpoints.len() - 1)].clone();
        let busy = self.busy.lock().unwrap().clone();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for container in shown {
                if let Some(asked) = self.row(ui, container, &endpoint, busy.contains(&container.id)) {
                    request = Some(asked);
                }
            }
        });
        request
    }

    fn header(&mut self, ui: &mut Ui, endpoints: &[Endpoint]) {
        ui.horizontal(|ui| {
            ui.label(RichText::new(&self.title).font(FontId::new(theme::size::HEADING, crate::ui::strong_family())).color(theme::text()));
            if endpoints.len() > 1 {
                ui.add_space(theme::space::M);
                // Con dos del mismo motor (de sistema y rootless) se distinguen por el socket.
                let repeated = |engine| endpoints.iter().filter(|e| e.engine == engine).count() > 1;
                let mut chosen = None;
                for (index, endpoint) in endpoints.iter().enumerate() {
                    let label = if repeated(endpoint.engine) { format!("{} · {}", endpoint.engine.name(), endpoint.socket.display()) } else { endpoint.engine.name().to_string() };
                    if ui.selectable_label(index == self.selected, label).hand().clicked() && index != self.selected {
                        chosen = Some(index);
                    }
                }
                if let Some(index) = chosen {
                    self.select(index);
                }
            } else if let Some(endpoint) = endpoints.first() {
                ui.label(RichText::new(endpoint.engine.name()).color(theme::subtext()));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(egui::Button::new(crate::ui::icons::REFRESH).frame(false)).on_hover_text("Actualizar ahora").hand().clicked() {
                    self.refresh.store(true, Ordering::SeqCst);
                }
                crate::ui::kit::switch_labeled(ui, &mut self.show_stopped, "Mostrar apagados");
                crate::ui::kit::search_field(ui, &mut self.search, "Buscar", 180.0);
            });
        });
    }

    fn empty(&mut self, ui: &mut Ui) {
        ui.add_space(theme::space::XXL);
        let title = match self.link() {
            Some(link) => format!("No se encontró Docker ni Podman en {}", link.name()),
            None => "No se encontró Docker ni Podman".to_string(),
        };
        ui.label(RichText::new(title).font(FontId::new(theme::size::HEADING, crate::ui::strong_family())).color(theme::text()));
        let places = if self.link().is_some() {
            "Inicia el motor en el servidor y vuelve a buscar. Se buscan DOCKER_HOST, /var/run/docker.sock, los sockets rootless del usuario y los de Podman."
        } else if cfg!(windows) {
            "Inicia Docker Desktop o la máquina de Podman y vuelve a buscar. Se busca la tubería de DOCKER_HOST, \\\\.\\pipe\\docker_engine y las de podman-machine."
        } else {
            "Inicia el motor y vuelve a buscar. Se buscan sus sockets en /var/run/docker.sock, en DOCKER_HOST y en el directorio de ejecución del usuario."
        };
        ui.label(RichText::new(places).color(theme::subtext()));
        ui.add_space(theme::space::XS);
        if ui.button("Buscar de nuevo").hand().clicked() {
            self.redetect();
        }
    }

    fn row(&self, ui: &mut Ui, container: &Container, endpoint: &Endpoint, working: bool) -> Option<Request> {
        let (rect, _) = crate::ui::kit::row_frame(ui, ROW_HEIGHT, Sense::hover());
        let mut request = None;

        let mut buttons = ui.new_child(UiBuilder::new().max_rect(rect.shrink2(Vec2::new(10.0, 0.0))).layout(Layout::right_to_left(Align::Center)));
        buttons.spacing_mut().item_spacing.x = 6.0;
        if container.is_running() {
            if IconButton::stop().enabled(!working).show(&mut buttons).on_hover_text("Detener").clicked() {
                request = Some(Request::Confirm(endpoint.clone(), container.clone(), Action::Stop));
            }
            if IconButton::new(crate::ui::icons::REFRESH).enabled(!working).show(&mut buttons).on_hover_text("Reiniciar").clicked() {
                request = Some(Request::Confirm(endpoint.clone(), container.clone(), Action::Restart));
            }
            if IconButton::new(crate::ui::icons::TERMINAL).enabled(!working).show(&mut buttons).on_hover_text("Abrir un terminal").clicked() {
                request = Some(Request::Terminal(endpoint.clone(), container.clone()));
            }
        } else {
            if IconButton::new(crate::ui::icons::PLAY).enabled(!working).show(&mut buttons).on_hover_text("Iniciar").clicked() {
                self.act(endpoint.clone(), container, Action::Start);
            }
            IconButton::new(crate::ui::icons::TERMINAL).enabled(false).show(&mut buttons).on_hover_text("Inicia el contenedor para abrir un terminal");
        }
        let text_right = buttons.min_rect().min.x - 12.0;

        let dot = if container.is_running() {
            theme::identity(3)
        } else if container.failed() {
            theme::red()
        } else {
            theme::subtext()
        };
        let status = if working { "Procesando…".to_string() } else { container.status.clone() };
        let mut detail = vec![container.image.clone(), status];
        if !container.ports.is_empty() {
            detail.push(container.ports.clone());
        }
        crate::ui::kit::row_content(
            ui,
            rect,
            crate::ui::kit::RowContent { leading: crate::ui::kit::Leading::Dot(dot), title: &container.name, subtitle: &detail.join("  ·  "), right_limit: text_right },
        );
        request
    }
}
