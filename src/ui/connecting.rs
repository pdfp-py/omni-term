//! Conectar: pedir las credenciales que falten y abrir la conexión.

use super::*;

impl App {
    /// Credenciales de una sola conexión: contraseña o passphrase si las necesita.
    pub(super) fn own_credentials(&mut self, connection: &Connection) -> Result<Credentials, Step> {
        let kind = match connection.auth {
            Auth::Password => Some(SecretKind::Password),
            Auth::Key => match connection.key_path.as_deref().map(ssh::key_is_encrypted) {
                Some(Ok(true)) => Some(SecretKind::Passphrase),
                Some(Err(error)) => return Err(Step::Failed(format!("{error:#}"))),
                _ => None,
            },
            Auth::Agent | Auth::Interactive => None,
        };
        let Some(kind) = kind else { return Ok(Credentials::default()) };
        let id = connection.id.unwrap_or_default();
        if let Some(secret) = self.session_secrets.get(&(id, kind)) {
            return Ok(credentials_for(kind, secret.clone()));
        }
        match self.secrets.get(&account_for(id, kind)) {
            Ok(Some(secret)) => Ok(credentials_for(kind, secret)),
            Ok(None) => Err(Step::Prompt { asking: connection.clone(), kind }),
            Err(SecretError::Locked) => Err(Step::Unlock),
            Err(error) => Err(Step::Failed(format!("Almacén de secretos: {error}"))),
        }
    }

    /// Credenciales de la conexión y de toda su cadena de servidores de salto.
    pub(super) fn gather_credentials(&mut self, connection: &Connection, depth: usize) -> Result<Credentials, Step> {
        let mut credentials = self.own_credentials(connection)?;
        if let Some(jump_id) = connection.jump {
            if depth >= 4 {
                return Err(Step::Failed("Demasiados saltos encadenados: revisa que no haya un ciclo".into()));
            }
            let Some(jump) = self.connections.iter().find(|c| c.id == Some(jump_id)).cloned() else {
                return Err(Step::Failed("El servidor de salto de esta conexión ya no existe".into()));
            };
            let jump_credentials = self.gather_credentials(&jump, depth + 1)?;
            credentials.jump = Some(Box::new(JumpHost { connection: jump, credentials: jump_credentials }));
        }
        Ok(credentials)
    }

    /// Credenciales para «Probar conexión»: el secreto escrito en el formulario o el ya guardado.
    /// Nunca pregunta: si falta algo, devuelve un mensaje que dice qué escribir.
    pub(super) fn test_credentials(&mut self, connection: &Connection, typed: &str) -> Result<Credentials, String> {
        let needs = match connection.auth {
            Auth::Password => Some(SecretKind::Password),
            Auth::Key => match connection.key_path.as_deref().map(ssh::key_is_encrypted) {
                Some(Ok(true)) => Some(SecretKind::Passphrase),
                Some(Err(error)) => return Err(format!("{error:#}")),
                _ => None,
            },
            Auth::Agent | Auth::Interactive => None,
        };
        let mut credentials = Credentials::default();
        if let Some(kind) = needs {
            let what = if kind == SecretKind::Password { "la contraseña" } else { "la passphrase" };
            if !typed.is_empty() {
                credentials = credentials_for(kind, Zeroizing::new(typed.to_string()));
            } else if connection.id.is_some() {
                credentials = match self.own_credentials(connection) {
                    Ok(found) => found,
                    Err(Step::Prompt { .. }) => return Err(format!("Escribe {what} en el formulario para poder probar.")),
                    Err(Step::Unlock) => {
                        return Err("El almacén de secretos está bloqueado: ábrelo antes con una conexión que use contraseña guardada.".into())
                    }
                    Err(Step::Failed(message)) => return Err(message),
                };
            } else {
                return Err(format!("Escribe {what} en el formulario para poder probar."));
            }
        }
        if let Some(jump_id) = connection.jump {
            let Some(jump) = self.connections.iter().find(|c| c.id == Some(jump_id)).cloned() else {
                return Err("El servidor de salto ya no existe.".into());
            };
            match self.gather_credentials(&jump, 1) {
                Ok(found) => credentials.jump = Some(Box::new(JumpHost { connection: jump, credentials: found })),
                Err(Step::Prompt { asking, .. }) => {
                    return Err(format!("«{}» necesita su contraseña guardada para poder pasar por él.", asking.name))
                }
                Err(Step::Unlock) => return Err("El almacén de secretos está bloqueado.".into()),
                Err(Step::Failed(message)) => return Err(message),
            }
        }
        Ok(credentials)
    }

    /// Reúne los secretos necesarios (pidiéndolos si hace falta) y abre la pestaña.
    pub(super) fn begin_open(&mut self, connection: Connection, slot: Option<u64>, purpose: Purpose) {
        // Las conexiones de archivos no tienen terminal: abrirlas es abrir su explorador.
        let purpose = if connection.is_files() && matches!(purpose, Purpose::Terminal) { Purpose::Explorer(None, None) } else { purpose };
        if connection.is_engine() {
            if !matches!(purpose, Purpose::Terminal) {
                self.notify("Un motor de contenedores no tiene explorador de archivos ni paneles");
                return;
            }
            // Volver a abrir el mismo motor lleva a su pestaña en lugar de duplicarla.
            let open = self.tabs.iter().position(|t| t.kind == TabKind::Connection(connection.id.unwrap_or(-1)) && matches!(t.body, Body::Containers(_)));
            if let Some(index) = open {
                self.active = index;
                return;
            }
        }
        if connection.is_local() {
            if matches!(purpose, Purpose::Explorer(..)) {
                self.notify("Un terminal local no tiene explorador de archivos");
            } else {
                self.finish_open(connection, Credentials::default(), slot, purpose);
            }
            return;
        }
        if connection.is_serial() {
            if matches!(purpose, Purpose::Explorer(..)) {
                self.notify("Un puerto serie no tiene explorador de archivos");
            } else {
                self.finish_open(connection, Credentials::default(), slot, purpose);
            }
            return;
        }
        if let Some(label) = connection.insecure_protocol() {
            let quiet = match connection.protocol {
                Protocol::Telnet(options) => options.quiet,
                Protocol::Files(store::FilesKind::Ftp(options)) => options.quiet,
                _ => true,
            };
            let reconnecting = slot.is_some() || matches!(purpose, Purpose::Pane { target: PaneTarget::Replace(_), .. });
            if !quiet && !reconnecting {
                self.dialog = Some(Dialog::TelnetWarning(dialogs::TelnetWarning { connection, slot, purpose, dont_ask: false, label }));
                return;
            }
        }
        self.continue_open(connection, slot, purpose);
    }

    /// Pide lo que falte (contraseñas) y abre la conexión.
    pub(super) fn continue_open(&mut self, connection: Connection, slot: Option<u64>, purpose: Purpose) {
        if connection.is_telnet() {
            // Telnet no tiene credenciales guardadas ni explorador de archivos.
            if matches!(purpose, Purpose::Explorer(..)) {
                self.notify("Telnet no tiene explorador de archivos");
            } else {
                self.finish_open(connection, Credentials::default(), slot, purpose);
            }
            return;
        }
        match self.gather_credentials(&connection, 0) {
            Ok(credentials) => self.finish_open(connection, credentials, slot, purpose),
            Err(Step::Prompt { asking, kind }) => {
                self.dialog = Some(Dialog::Secret(SecretPrompt {
                    purpose,
                    connection,
                    asking,
                    slot,
                    kind,
                    input: String::new(),
                    save: true,
                    reveal: false,
                }));
            }
            Err(Step::Unlock) => self.ask_unlock(Pending::Open(connection, slot, purpose)),
            Err(Step::Failed(message)) => self.dialog = Some(Dialog::failure("No se pudo preparar la conexión", message)),
        }
    }

    /// Anota la conexión como la usada más recientemente (solo aperturas nuevas, no reconexiones).
    pub(super) fn touch_recent(&mut self, id: i64) {
        self.recent.retain(|(r, _)| *r != id);
        self.recent.insert(0, (id, now_secs()));
        self.recent.truncate(20);
        let text = self.recent.iter().map(|(id, at)| format!("{id}:{at}")).collect::<Vec<_>>().join(",");
        let _ = self.store.lock().unwrap().set_meta("recent_connections", text.as_bytes());
    }

    pub(super) fn finish_open(&mut self, connection: Connection, credentials: Credentials, slot: Option<u64>, purpose: Purpose) {
        if slot.is_none() && !matches!(purpose, Purpose::Pane { .. }) {
            if let Some(id) = connection.id {
                self.touch_recent(id);
            }
        }
        let retry = Retry::Open(connection.clone(), slot, purpose.clone());
        let result = match purpose {
            Purpose::Terminal if connection.is_engine() => self.open_engine(connection, credentials),
            Purpose::Terminal => self.open_ssh(connection, credentials, slot),
            Purpose::Explorer(local, remote) => self.open_explorer(connection, credentials, (local, remote)),
            Purpose::Pane { tab, target } => self.open_ssh_pane(connection, credentials, tab, target),
        };
        if let Err(error) = result {
            self.dialog = Some(Dialog::Error(ErrorInfo {
                title: "No se pudo abrir la conexión".into(),
                detail: format!("{error:#}"),
                retry: Some(retry),
            }));
        }
    }
}

/// Qué falta para poder abrir una conexión.
pub(super) enum Step {
    Prompt { asking: Connection, kind: SecretKind },
    Unlock,
    Failed(String),
}

pub(super) fn credentials_for(kind: SecretKind, secret: Zeroizing<String>) -> Credentials {
    match kind {
        SecretKind::Password => Credentials { password: Some(secret), ..Default::default() },
        SecretKind::Passphrase => Credentials { key_passphrase: Some(secret), ..Default::default() },
    }
}
