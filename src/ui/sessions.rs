//! Abrir sesiones y pestañas: terminales, paneles, explorador y administrador de contenedores.

use super::*;

impl App {
    /// Terminal local nuevo: el del perfil elegido como predeterminado en Ajustes, o el shell del sistema.
    pub(super) fn local_session(&mut self) -> anyhow::Result<Session> {
        let default = self.settings.local_profile.and_then(|id| self.connections.iter().find(|c| c.id == Some(id) && c.is_local()).cloned());
        match default {
            Some(profile) => self.local_profile_session(profile),
            None => self.local_profile_session_with(crate::connect::local::Profile::default()),
        }
    }

    pub(super) fn local_profile_session(&mut self, connection: Connection) -> anyhow::Result<Session> {
        self.local_profile_session_with(crate::connect::local::Profile::from_connection(&connection))
    }

    pub(super) fn local_profile_session_with(&mut self, profile: crate::connect::local::Profile) -> anyhow::Result<Session> {
        let wake = self.wake();
        let (cols, rows) = self.grid;
        let options = self.term_options();
        Session::start(cols, rows, options, move || wake(), move |feed| crate::connect::local::spawn_profile(cols, rows, feed, &profile))
    }

    pub(super) fn ssh_session(&mut self, connection: Connection, credentials: Credentials, tunnels: Tunnels) -> anyhow::Result<Session> {
        let wake = self.wake();
        let wake_for_ssh = wake.clone();
        let handle = self.runtime.handle().clone();
        let events = self.events_tx.clone();
        let (cols, rows) = self.grid;
        let options = self.term_options();
        Session::start(cols, rows, options, move || wake(), move |feed| {
            Ok(ssh::spawn(&handle, connection, credentials, (cols, rows), feed, events, wake_for_ssh, ssh::default_known_hosts(), tunnels))
        })
    }

    pub(super) fn telnet_session(&mut self, connection: Connection) -> anyhow::Result<Session> {
        let wake = self.wake();
        let handle = self.runtime.handle().clone();
        let (cols, rows) = self.grid;
        let options = self.term_options();
        Session::start(cols, rows, options, move || wake(), move |feed| Ok(telnet::spawn(&handle, connection, (cols, rows), feed)))
    }

    pub(super) fn adb_session(&mut self, connection: Connection) -> anyhow::Result<Session> {
        let wake = self.wake();
        let handle = self.runtime.handle().clone();
        let (cols, rows) = self.grid;
        let options = self.term_options();
        Session::start(cols, rows, options, move || wake(), move |feed| Ok(crate::files::adb::spawn(&handle, connection, (cols, rows), feed)))
    }

    pub(super) fn serial_session(&mut self, connection: Connection) -> anyhow::Result<Session> {
        let wake = self.wake();
        let (cols, rows) = self.grid;
        let options = self.term_options();
        Session::start(cols, rows, options, move || wake(), move |feed| Ok(crate::connect::serial::spawn(&connection, feed)))
    }

    /// ¿La pestaña activa es una conexión con explorador de archivos (SSH o un dispositivo Android)?
    pub(super) fn active_has_explorer(&self) -> bool {
        match self.tabs.get(self.active).map(|t| t.kind) {
            Some(TabKind::Connection(id)) => self.connections.iter().any(|c| c.id == Some(id) && (c.is_ssh() || c.is_adb())),
            _ => false,
        }
    }

    /// Sesión de terminal de una conexión: SSH, Telnet, puerto serie o Android.
    pub(super) fn connection_session(&mut self, connection: Connection, credentials: Credentials, tunnels: Tunnels) -> anyhow::Result<Session> {
        if connection.is_local() {
            self.local_profile_session(connection)
        } else if connection.is_serial() {
            self.serial_session(connection)
        } else if connection.is_adb() {
            self.adb_session(connection)
        } else if connection.is_telnet() {
            self.telnet_session(connection)
        } else {
            self.ssh_session(connection, credentials, tunnels)
        }
    }

    pub(super) fn open_local(&mut self) -> anyhow::Result<()> {
        let session = self.local_session()?;
        let id = self.take_tab_id();
        let body = Body::terminal(Pane::new(session, self.debug_keys, 1), None);
        self.tabs.push(Tab { id, kind: TabKind::Local, label: "Terminal local".into(), custom: None, attention: false, body });
        self.active = self.tabs.len() - 1;
        Ok(())
    }

    /// Abre la pestaña de ajustes en la sección pedida, o vuelve a ella si ya está abierta.
    pub(super) fn open_settings(&mut self, section: dialogs::SettingsTab) {
        self.known_hosts.loaded = false;
        if let Some(index) = self.tabs.iter().position(|t| t.kind == TabKind::Settings) {
            self.tabs[index].body = Body::Settings(section);
            self.active = index;
            return;
        }
        let id = self.take_tab_id();
        self.tabs.push(Tab { id, kind: TabKind::Settings, label: "Ajustes".into(), custom: None, attention: false, body: Body::Settings(section) });
        self.active = self.tabs.len() - 1;
    }

    /// Abre el administrador de contenedores, o vuelve a él si ya hay uno abierto.
    pub(super) fn open_containers(&mut self) {
        if let Some(index) = self.tabs.iter().position(|t| t.kind == TabKind::Containers) {
            self.active = index;
            return;
        }
        let view = ContainersView::new(self.runtime.handle().clone(), self.wake(), view::Source::Here, "Contenedores".into());
        let id = self.take_tab_id();
        self.tabs.push(Tab { id, kind: TabKind::Containers, label: "Contenedores".into(), custom: None, attention: false, body: Body::Containers(Box::new(view)) });
        self.active = self.tabs.len() - 1;
    }

    /// Pestaña de contenedores de un perfil de motor: en este equipo o en un servidor por SSH.
    pub(super) fn open_engine(&mut self, connection: Connection, credentials: Credentials) -> anyhow::Result<()> {
        let Some(id) = connection.id else { anyhow::bail!("la conexión no está guardada") };
        let socket = connection.engine_socket().map(str::to_string);
        let source = match (credentials.jump, connection.jump) {
            (Some(server), _) => {
                let link = ssh::SshLink::new(*server, self.events_tx.clone(), self.wake(), ssh::default_known_hosts());
                view::Source::Remote { link: Arc::new(link), socket }
            }
            (None, Some(_)) => anyhow::bail!("La conexión SSH de este motor ya no existe: edítalo y elige otra."),
            (None, None) => match socket {
                Some(socket) => view::Source::Socket(socket),
                None => view::Source::Here,
            },
        };
        let title = format!("Contenedores · {}", connection.name);
        let view = ContainersView::new(self.runtime.handle().clone(), self.wake(), source, title.clone());
        let tab_id = self.take_tab_id();
        self.tabs.push(Tab { id: tab_id, kind: TabKind::Connection(id), label: title, custom: None, attention: false, body: Body::Containers(Box::new(view)) });
        self.active = self.tabs.len() - 1;
        Ok(())
    }

    /// Sesión de un shell dentro de un contenedor. Se abre por nombre, que sobrevive a que se recree.
    fn container_session(&mut self, endpoint: docker::Endpoint, name: String) -> anyhow::Result<Session> {
        let wake = self.wake();
        let handle = self.runtime.handle().clone();
        let (cols, rows) = self.grid;
        let options = self.term_options();
        Session::start(cols, rows, options, move || wake(), move |feed| Ok(docker::spawn(&handle, endpoint, name.clone(), name, (cols, rows), feed)))
    }

    /// Terminal dentro de un contenedor, en una pestaña nueva.
    pub(super) fn open_container_terminal(&mut self, endpoint: docker::Endpoint, container: &docker::Container) {
        let label = match &endpoint.via {
            docker::Via::Ssh(link) => format!("{} · {}", container.name, link.name()),
            docker::Via::Local => container.name.clone(),
        };
        match self.container_session(endpoint.clone(), container.name.clone()) {
            Ok(session) => {
                let tab_id = self.take_tab_id();
                let body = Body::terminal(Pane::new(session, self.debug_keys, 1), None);
                self.tabs.push(Tab { id: tab_id, kind: TabKind::Container, label, custom: None, attention: false, body });
                self.container_shells.insert(tab_id, (endpoint, container.name.clone()));
                self.active = self.tabs.len() - 1;
            }
            Err(error) => self.dialog = Some(Dialog::failure("No se pudo abrir el terminal", format!("{error:#}"))),
        }
    }

    /// Abre un shell nuevo en el mismo contenedor; si la sesión SSH del motor se cayó, se reconecta antes.
    fn reconnect_container(&mut self, index: usize) {
        let tab_id = self.tabs[index].id;
        let Some((endpoint, name)) = self.container_shells.get(&tab_id).cloned() else { return };
        // Permite reconectar; el shell nuevo abre la sesión al conectar.
        if let docker::Via::Ssh(link) = &endpoint.via {
            link.reconnect();
        }
        match self.container_session(endpoint, name) {
            Ok(session) => self.tabs[index].body = Body::terminal(Pane::new(session, self.debug_keys, 1), None),
            Err(error) => self.dialog = Some(Dialog::failure("No se pudo reabrir el terminal", format!("{error:#}"))),
        }
    }

    /// Ejecuta una acción confirmada sobre un contenedor, en la pestaña del motor al que pertenece.
    pub(super) fn container_action(&mut self, confirm: dialogs::ContainerConfirm) {
        let view = self.tabs.iter().find_map(|t| match &t.body {
            Body::Containers(view) if view.current_endpoint().as_ref() == Some(&confirm.endpoint) => Some(view),
            _ => None,
        });
        if let Some(view) = view {
            view.act(confirm.endpoint, &confirm.container, confirm.action);
        }
    }

    pub(super) fn take_tab_id(&mut self) -> u64 {
        self.next_tab_id += 1;
        self.next_tab_id
    }

    /// Abre la sesión SSH en una pestaña nueva o, con `slot`, en lugar de una caída.
    pub(super) fn open_ssh(&mut self, connection: Connection, credentials: Credentials, slot: Option<u64>) -> anyhow::Result<()> {
        let Some(id) = connection.id else { anyhow::bail!("la conexión no está guardada") };
        let label = connection.name.clone();
        let forwards = self.forwards.get(&id).cloned().unwrap_or_default();
        let tunnels = ssh::new_tunnels(&forwards);
        let session = self.connection_session(connection, credentials, tunnels.clone())?;
        let tab_id = slot.unwrap_or_else(|| self.take_tab_id());
        let body = Body::terminal(Pane::new(session, self.debug_keys, 1), Some(tunnels));
        let mut tab = Tab { id: tab_id, kind: TabKind::Connection(id), label, custom: None, attention: false, body };
        match slot.and_then(|slot| self.tabs.iter().position(|t| t.id == slot)) {
            Some(index) => {
                tab.custom = self.tabs[index].custom.take();
                self.tabs[index] = tab;
                self.active = index;
            }
            None => {
                self.tabs.push(tab);
                self.active = self.tabs.len() - 1;
            }
        }
        Ok(())
    }

    /// Añade o sustituye un panel SSH dentro de una pestaña de terminal.
    pub(super) fn open_ssh_pane(&mut self, connection: Connection, credentials: Credentials, tab: u64, target: PaneTarget) -> anyhow::Result<()> {
        let session = self.connection_session(connection, credentials, ssh::new_tunnels(&[]))?;
        self.place_pane(tab, target, session);
        Ok(())
    }

    pub(super) fn place_pane(&mut self, tab: u64, target: PaneTarget, session: Session) {
        let debug_keys = self.debug_keys;
        let Some(Body::Terminal { panes, focused, next_pane, .. }) =
            self.tabs.iter_mut().find(|t| t.id == tab).map(|t| &mut t.body)
        else {
            return;
        };
        match target {
            PaneTarget::Split(dir) => {
                let id = *next_pane;
                *next_pane += 1;
                if panes.split(*focused, dir, id, Pane::new(session, debug_keys, id)) {
                    *focused = id;
                }
            }
            PaneTarget::Replace(id) => {
                if let Some(slot) = panes.get_mut(id) {
                    *slot = Pane::new(session, debug_keys, id);
                }
            }
        }
    }

    /// Divide el panel con foco de la pestaña activa con un terminal nuevo del mismo tipo.
    pub(super) fn split_active(&mut self, dir: Dir) {
        let Some(tab) = self.tabs.get(self.active) else { return };
        let (tab_id, kind) = (tab.id, tab.kind);
        if !matches!(tab.body, Body::Terminal { .. }) {
            return;
        }
        match kind {
            TabKind::Local => match self.local_session() {
                Ok(session) => self.place_pane(tab_id, PaneTarget::Split(dir), session),
                Err(error) => self.dialog = Some(Dialog::failure("No se pudo abrir el terminal", format!("{error:#}"))),
            },
            TabKind::Connection(id) => {
                if let Some(connection) = self.connections.iter().find(|c| c.id == Some(id)).cloned() {
                    self.begin_open(connection, None, Purpose::Pane { tab: tab_id, target: PaneTarget::Split(dir) });
                }
            }
            TabKind::Explorer(_) | TabKind::Containers | TabKind::Container | TabKind::Settings => {}
        }
    }

    /// Cierra el panel con foco; si es el único, cierra la pestaña.
    pub(super) fn close_focused_pane(&mut self) {
        let active = self.active;
        let Some(tab) = self.tabs.get_mut(active) else { return };
        match &mut tab.body {
            Body::Terminal { panes, focused, .. } if panes.len() > 1 => {
                let closing = *focused;
                if panes.remove(closing) {
                    *focused = panes.ids().first().copied().unwrap_or(1);
                }
            }
            _ => self.close_tab(active),
        }
    }

    /// Abre un explorador de archivos con su propia sesión SSH.
    pub(super) fn open_explorer(&mut self, connection: Connection, credentials: Credentials, paths: (Option<String>, Option<String>)) -> anyhow::Result<()> {
        let Some(id) = connection.id else { anyhow::bail!("la conexión no está guardada") };
        let label = format!("Archivos · {}", connection.name);
        let explorer = Explorer::new(
            connection,
            credentials,
            self.runtime.handle().clone(),
            self.wake(),
            self.events_tx.clone(),
            ssh::default_known_hosts(),
            paths,
        );
        let tab_id = self.take_tab_id();
        self.tabs.push(Tab { id: tab_id, kind: TabKind::Explorer(id), label, custom: None, attention: false, body: Body::Explorer(Box::new(explorer)) });
        self.active = self.tabs.len() - 1;
        Ok(())
    }

    pub(super) fn reconnect(&mut self, index: usize) {
        if self.tabs[index].kind == TabKind::Container {
            self.reconnect_container(index);
            return;
        }
        let (TabKind::Connection(id), tab_id) = (self.tabs[index].kind, self.tabs[index].id) else { return };
        let split_focus = match &self.tabs[index].body {
            Body::Terminal { panes, focused, .. } if panes.len() > 1 => Some(*focused),
            _ => None,
        };
        if let Some(connection) = self.connections.iter().find(|c| c.id == Some(id)).cloned() {
            match split_focus {
                // Con paneles divididos solo se reconecta el panel caído.
                Some(pane) => self.begin_open(connection, None, Purpose::Pane { tab: tab_id, target: PaneTarget::Replace(pane) }),
                None => self.begin_open(connection, Some(tab_id), Purpose::Terminal),
            }
        }
    }
}
