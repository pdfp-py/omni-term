//! Modelo del formulario de conexión: campos, validación y conversión a `Connection`.

use super::*;

/// Atajos de entorno: nombre del botón, etiqueta que se guarda y color de identidad.
pub(super) const ENVIRONMENTS: [(&str, &str, u8); 4] = [
    ("Producción", "producción", 0),
    ("Staging", "staging", 1),
    ("Desarrollo", "desarrollo", 3),
    ("Personal", "personal", 4),
];

pub struct ForwardRow {
    pub kind: ForwardKind,
    pub bind_host: String,
    pub bind_port: String,
    pub dest_host: String,
    pub dest_port: String,
}

impl ForwardRow {
    pub(super) fn new() -> Self {
        Self {
            kind: ForwardKind::Local,
            bind_host: "127.0.0.1".into(),
            bind_port: String::new(),
            dest_host: "localhost".into(),
            dest_port: String::new(),
        }
    }

    pub(super) fn from_forward(forward: &Forward) -> Self {
        Self {
            kind: forward.kind,
            bind_host: forward.bind_host.clone(),
            bind_port: forward.bind_port.to_string(),
            dest_host: forward.dest_host.clone(),
            dest_port: forward.dest_port.to_string(),
        }
    }

    pub(super) fn to_forward(&self) -> Result<Forward, String> {
        let port = |text: &str, what: &str| -> Result<u16, String> {
            match text.trim().parse::<u16>() {
                Ok(port) if port > 0 => Ok(port),
                _ => Err(format!("El puerto {what} de un túnel debe estar entre 1 y 65535")),
            }
        };
        let bind_host = self.bind_host.trim();
        if bind_host.is_empty() {
            return Err("Cada túnel necesita una dirección de escucha".into());
        }
        if self.kind == ForwardKind::Dynamic {
            return Ok(Forward {
                kind: self.kind,
                bind_host: bind_host.into(),
                bind_port: port(&self.bind_port, "de escucha")?,
                dest_host: String::new(),
                dest_port: 0,
            });
        }
        let dest_host = self.dest_host.trim();
        if dest_host.is_empty() {
            return Err("Cada túnel necesita dirección de destino".into());
        }
        Ok(Forward {
            kind: self.kind,
            bind_host: bind_host.into(),
            bind_port: port(&self.bind_port, "de escucha")?,
            dest_host: dest_host.into(),
            dest_port: port(&self.dest_port, "de destino")?,
        })
    }
}

impl ForwardRow {
    /// Un túnel `-L` o `-D` que escucha fuera de este equipo lo puede usar cualquiera de la red.
    pub(super) fn listens_on_network(&self) -> bool {
        let host = self.bind_host.trim().trim_matches(['[', ']']);
        self.kind != ForwardKind::Remote
            && !host.is_empty()
            && !host.eq_ignore_ascii_case("localhost")
            && host != "::1"
            && !host.starts_with("127.")
    }
}

/// Resultado de «Probar conexión», actualizado desde una tarea en segundo plano.
pub enum TestState {
    Running,
    Ok(String),
    Failed(String),
}

pub type TestHandle = std::sync::Arc<std::sync::Mutex<TestState>>;

/// Errores de validación, pegados al campo que los causa.
#[derive(Default)]
pub struct FormErrors {
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub user: Option<String>,
    pub key_path: Option<String>,
    pub share: Option<String>,
    /// Carpeta inicial de un perfil local.
    pub cwd: Option<String>,
    pub forwards: Vec<Option<String>>,
    /// Error al guardar que no pertenece a ningún campo.
    pub general: Option<String>,
}

pub type AdbDevices = std::sync::Arc<std::sync::Mutex<Option<Result<Vec<crate::files::adb::Device>, String>>>>;

pub struct ConnForm {
    /// 0 no es de archivos; 1 SFTP; 2 FTP; 3 SMB.
    pub files: u8,
    pub ftp_tls: FtpTls,
    pub ftp_passive: bool,
    pub ftp_anonymous: bool,
    pub ftp_quiet: bool,
    pub smb_share: String,
    pub smb_domain: String,
    /// Dispositivo Android por `adb`; el número de serie (o `ip:puerto`) va en `host`.
    pub adb: bool,
    /// Resultado de la última búsqueda de dispositivos, que corre en segundo plano.
    pub adb_devices: Option<AdbDevices>,
    /// Perfil de terminal local: intérprete en `host`, argumentos en `local_args`, carpeta en `local_cwd`.
    pub local: bool,
    /// Motor de contenedores: `host` es el socket (vacío = detectar) y `jump` la conexión SSH.
    pub engine: bool,
    pub local_args: String,
    pub local_cwd: String,
    pub local_vars: String,
    /// Se eligió «Otro…» en la lista de intérpretes: la ruta se escribe a mano.
    pub local_other: bool,
    /// Conexión por puerto serie; el puerto va en `host`.
    pub serial: bool,
    pub baud: String,
    pub data_bits: u8,
    pub parity: Parity,
    pub stop_bits: u8,
    pub flow: Flow,
    pub newline: Newline,
    pub local_echo: bool,
    /// Puertos detectados la última vez que se pulsó «Detectar».
    pub ports: Vec<(String, String)>,
    /// Conexión Telnet en lugar de SSH.
    pub telnet: bool,
    pub negotiate: bool,
    pub encoding: Encoding,
    /// Se conserva el «no avisar» de la conexión que se edita.
    pub quiet: bool,
    /// Pide el foco para «Nombre» la primera vez que se dibuja.
    pub focus: bool,
    /// Muestra la etiqueta y los colores a mano en vez de los atajos de entorno.
    pub custom_env: bool,
    /// «Avanzado» desplegado.
    pub advanced_open: bool,
    pub errors: FormErrors,
    pub test: Option<TestHandle>,
    pub color: Option<u8>,
    pub env: String,
    pub jump: Option<i64>,
    pub forwards: Vec<ForwardRow>,
    pub id: Option<i64>,
    pub name: String,
    pub host: String,
    pub port: String,
    pub user: String,
    pub auth: Auth,
    pub key_path: String,
    pub init_command: String,
    pub secret: String,
    pub reveal_secret: bool,
}

impl ConnForm {
    pub fn new() -> Self {
        let serial = SerialOptions::default();
        Self {
            files: 0,
            ftp_tls: FtpTls::None,
            ftp_passive: true,
            ftp_anonymous: false,
            ftp_quiet: false,
            smb_share: String::new(),
            smb_domain: String::new(),
            adb: false,
            adb_devices: None,
            local: false,
            engine: false,
            local_args: String::new(),
            local_cwd: String::new(),
            local_vars: String::new(),
            local_other: false,
            serial: false,
            baud: serial.baud.to_string(),
            data_bits: serial.data_bits,
            parity: serial.parity,
            stop_bits: serial.stop_bits,
            flow: serial.flow,
            newline: serial.newline,
            local_echo: serial.local_echo,
            ports: Vec::new(),
            telnet: false,
            negotiate: true,
            encoding: Encoding::Utf8,
            quiet: false,
            id: None,
            name: String::new(),
            host: String::new(),
            port: "22".into(),
            user: std::env::var("USER").unwrap_or_default(),
            auth: Auth::Agent,
            key_path: "~/.ssh/id_ed25519".into(),
            init_command: String::new(),
            secret: String::new(),
            reveal_secret: false,
            focus: true,
            custom_env: false,
            advanced_open: false,
            errors: FormErrors::default(),
            test: None,
            forwards: Vec::new(),
            jump: None,
            color: None,
            env: String::new(),
        }
    }

    pub fn is_ssh(&self) -> bool {
        !self.telnet && !self.serial && !self.adb && !self.local && !self.engine && self.files == 0
    }

    /// Usa los campos de SSH (usuario, acceso, llave, salto): SSH y SFTP.
    pub fn ssh_like(&self) -> bool {
        self.is_ssh() || self.files == 1
    }

    pub fn from_connection(connection: &Connection, forwards: &[Forward]) -> Self {
        let env = connection.env.clone().unwrap_or_default();
        let known = ENVIRONMENTS.iter().any(|(_, name, color)| env.eq_ignore_ascii_case(name) && connection.color == Some(*color));
        let custom_env = !known && (!env.is_empty() || connection.color.is_some());
        let options = match connection.protocol {
            Protocol::Telnet(options) => Some(options),
            _ => None,
        };
        let serial = match connection.protocol {
            Protocol::Serial(options) => Some(options),
            _ => None,
        };
        let serial_defaults = serial.unwrap_or_default();
        let (files, ftp) = match connection.protocol {
            Protocol::Files(FilesKind::Sftp) => (1, FtpOptions::default()),
            Protocol::Files(FilesKind::Ftp(options)) => (2, options),
            Protocol::Files(FilesKind::Smb) => (3, FtpOptions::default()),
            _ => (0, FtpOptions::default()),
        };
        Self {
            files,
            ftp_tls: ftp.tls,
            ftp_passive: ftp.passive,
            ftp_anonymous: ftp.anonymous,
            ftp_quiet: ftp.quiet,
            smb_share: if files == 3 { connection.smb_share().to_string() } else { String::new() },
            smb_domain: if files == 3 { connection.smb_domain().to_string() } else { String::new() },
            adb: connection.is_adb(),
            adb_devices: None,
            local: connection.is_local(),
            engine: connection.is_engine(),
            local_args: if connection.is_local() { connection.user.clone() } else { String::new() },
            local_cwd: if connection.is_local() { connection.key_path.clone().unwrap_or_default() } else { String::new() },
            local_vars: connection.vars.clone(),
            local_other: false,
            serial: serial.is_some(),
            baud: serial_defaults.baud.to_string(),
            data_bits: serial_defaults.data_bits,
            parity: serial_defaults.parity,
            stop_bits: serial_defaults.stop_bits,
            flow: serial_defaults.flow,
            newline: serial_defaults.newline,
            local_echo: serial_defaults.local_echo,
            ports: Vec::new(),
            telnet: options.is_some(),
            negotiate: options.map_or(true, |o| o.negotiate),
            encoding: options.map_or(Encoding::Utf8, |o| o.encoding),
            quiet: options.is_some_and(|o| o.quiet),
            focus: true,
            custom_env,
            jump: connection.jump,
            color: connection.color,
            env,
            forwards: forwards.iter().map(ForwardRow::from_forward).collect(),
            id: connection.id,
            name: connection.name.clone(),
            host: connection.host.clone(),
            port: connection.port.to_string(),
            user: connection.user.clone(),
            auth: connection.auth,
            key_path: connection.key_path.clone().unwrap_or_default(),
            init_command: connection.init_command.clone().unwrap_or_default(),
            secret: String::new(),
            reveal_secret: false,
            advanced_open: connection.jump.is_some(),
            errors: FormErrors::default(),
            test: None,
        }
    }

    /// Valida el formulario. Si hay errores los deja junto a cada campo, cambia a la pestaña
    /// del primero y devuelve `None`; si no, devuelve la conexión y sus túneles.
    pub fn validate(&mut self) -> Option<(Connection, Vec<Forward>)> {
        let mut errors = FormErrors::default();
        let name = self.name.trim().to_string();
        let host = self.host.trim().to_string();
        let user = self.user.trim().to_string();
        if name.is_empty() {
            errors.name = Some("Pon un nombre para reconocerla".into());
        }
        if self.local {
            if !crate::connect::local::program_exists(&host) {
                errors.host = Some("No se encuentra ese intérprete".into());
            }
            if crate::connect::local::split_args(&self.local_args).is_err() {
                errors.user = Some("Falta cerrar unas comillas".into());
            }
            if !crate::connect::local::dir_exists(&self.local_cwd) {
                errors.cwd = Some("Esa carpeta no existe".into());
            }
        }
        if host.is_empty() && !self.adb && !self.local && !self.engine {
            errors.host = Some(if self.serial { "Indica el puerto, por ejemplo /dev/ttyUSB0" } else { "Indica el servidor" }.into());
        }
        let mut baud = 0;
        if self.serial {
            match self.baud.trim().parse::<u32>() {
                Ok(value) if value > 0 => baud = value,
                _ => errors.port = Some("Una velocidad mayor que 0".into()),
            }
        }
        let user_needed = self.ssh_like() || self.files == 3 || (self.files == 2 && !self.ftp_anonymous);
        if user.is_empty() && user_needed {
            errors.user = Some("Indica el usuario".into());
        }
        if self.files == 3 && self.smb_share.trim().trim_matches(['\\', '/']).is_empty() {
            errors.share = Some("Indica el recurso compartido".into());
        }
        let port = if self.serial || self.adb || self.local || self.engine {
            0
        } else {
            match self.port.trim().parse::<u16>() {
                Ok(port) if port > 0 => port,
                _ => {
                    errors.port = Some("Un número entre 1 y 65535".into());
                    0
                }
            }
        };
        let key_path = self.key_path.trim().to_string();
        if self.auth == Auth::Key && key_path.is_empty() {
            errors.key_path = Some("Indica la ruta de la llave privada".into());
        }
        let mut forwards = Vec::new();
        for row in self.forwards.iter().filter(|_| self.is_ssh()) {
            match row.to_forward() {
                Ok(forward) => {
                    forwards.push(forward);
                    errors.forwards.push(None);
                }
                Err(message) => errors.forwards.push(Some(message)),
            }
        }

        let has_error = [&errors.name, &errors.host, &errors.port, &errors.user, &errors.key_path, &errors.share, &errors.cwd].iter().any(|e| e.is_some())
            || errors.forwards.iter().any(Option::is_some);
        if has_error {
            self.advanced_open |= errors.forwards.iter().any(Option::is_some);
            crate::ui::kit::request_reveal_error();
            self.errors = errors;
            return None;
        }
        self.errors = FormErrors::default();
        let telnet = self.telnet || self.serial || self.adb || self.local || self.engine || self.files >= 2;
        let anonymous = self.files == 2 && self.ftp_anonymous;
        let connection = Connection {
            id: self.id,
            protocol: if self.files > 0 {
                Protocol::Files(match self.files {
                    1 => FilesKind::Sftp,
                    2 => FilesKind::Ftp(FtpOptions { tls: self.ftp_tls, passive: self.ftp_passive, anonymous: self.ftp_anonymous, quiet: self.ftp_quiet }),
                    _ => FilesKind::Smb,
                })
            } else if self.adb {
                Protocol::Adb
            } else if self.local {
                Protocol::Local
            } else if self.engine {
                Protocol::Engine
            } else if self.serial {
                Protocol::Serial(SerialOptions {
                    baud,
                    data_bits: self.data_bits,
                    parity: self.parity,
                    stop_bits: self.stop_bits,
                    flow: self.flow,
                    newline: self.newline,
                    local_echo: self.local_echo,
                })
            } else if self.telnet {
                Protocol::Telnet(TelnetOptions { negotiate: self.negotiate, encoding: self.encoding, quiet: self.quiet })
            } else {
                Protocol::Ssh
            },
            name,
            host,
            port,
            user: if anonymous { "anonymous".into() } else if self.local { self.local_args.trim().to_string() } else if self.telnet || self.serial || self.adb || self.engine { String::new() } else { user },
            // FTP y SMB piden la contraseña al conectar; el anónimo no la pide.
            auth: match self.files {
                2 if anonymous => Auth::Agent,
                2 | 3 => Auth::Password,
                _ if telnet => Auth::Agent,
                _ => self.auth,
            },
            key_path: if self.local {
                Some(self.local_cwd.trim().to_string()).filter(|d| !d.is_empty())
            } else if self.files == 3 {
                Some(self.smb_domain.trim().to_string()).filter(|d| !d.is_empty())
            } else {
                (!telnet && self.auth == Auth::Key).then_some(key_path)
            },
            init_command: if self.files == 3 {
                Some(self.smb_share.trim().trim_matches(['\\', '/']).to_string())
            } else {
                Some(self.init_command.trim().to_string()).filter(|c| !c.is_empty() && (!telnet || self.local))
            },
            // Un motor guarda aquí la conexión SSH por la que se llega a él.
            jump: if self.engine || !telnet { self.jump } else { None },
            color: self.color,
            env: Some(self.env.trim().to_string()).filter(|e| !e.is_empty()),
            vars: if self.local { self.local_vars.trim().to_string() } else { String::new() },
        };
        Some((connection, forwards))
    }
}
