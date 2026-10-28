//! Persistencia en SQLite: conexiones guardadas, layout de pestañas y secretos cifrados.

use std::path::Path;

use anyhow::{bail, Context};
use rusqlite::{params, Connection as Db, OptionalExtension};

// Las migraciones solo se añaden al final: reordenarlas rompe las bases de datos ya creadas.
const MIGRATIONS: &[&str] = &[
    "CREATE TABLE connections (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 22,
        user TEXT NOT NULL,
        auth TEXT NOT NULL,
        key_path TEXT,
        init_command TEXT
    );
    CREATE TABLE layout_tabs (
        position INTEGER PRIMARY KEY,
        connection_id INTEGER REFERENCES connections(id) ON DELETE CASCADE
    );
    CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
    CREATE TABLE secrets (
        account TEXT PRIMARY KEY,
        nonce BLOB NOT NULL,
        ciphertext BLOB NOT NULL
    );",
    "CREATE TABLE forwards (
        id INTEGER PRIMARY KEY,
        connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
        position INTEGER NOT NULL,
        kind TEXT NOT NULL,
        bind_host TEXT NOT NULL,
        bind_port INTEGER NOT NULL,
        dest_host TEXT NOT NULL,
        dest_port INTEGER NOT NULL
    );",
    "CREATE TABLE snippets (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        tag TEXT NOT NULL DEFAULT '',
        body TEXT NOT NULL
    );",
    "ALTER TABLE layout_tabs ADD COLUMN kind TEXT NOT NULL DEFAULT 'auto';
     ALTER TABLE layout_tabs ADD COLUMN local_path TEXT;
     ALTER TABLE layout_tabs ADD COLUMN remote_path TEXT;",
    "ALTER TABLE connections ADD COLUMN jump_id INTEGER REFERENCES connections(id) ON DELETE SET NULL;",
    "ALTER TABLE connections ADD COLUMN color INTEGER;
     ALTER TABLE connections ADD COLUMN env TEXT;",
    "ALTER TABLE connections ADD COLUMN protocol TEXT NOT NULL DEFAULT 'ssh';
     ALTER TABLE connections ADD COLUMN telnet_raw INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE connections ADD COLUMN encoding TEXT NOT NULL DEFAULT 'utf8';
     ALTER TABLE connections ADD COLUMN telnet_quiet INTEGER NOT NULL DEFAULT 0;",
    "ALTER TABLE connections ADD COLUMN serial_opts TEXT;",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    Password,
    Key,
    Agent,
    /// Preguntas del servidor (keyboard-interactive), por ejemplo contraseña más código 2FA.
    Interactive,
}

impl Auth {
    fn as_str(self) -> &'static str {
        match self {
            Auth::Password => "password",
            Auth::Key => "key",
            Auth::Agent => "agent",
            Auth::Interactive => "interactive",
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "password" => Ok(Auth::Password),
            "key" => Ok(Auth::Key),
            "agent" => Ok(Auth::Agent),
            "interactive" => Ok(Auth::Interactive),
            other => bail!("método de autenticación desconocido: {other}"),
        }
    }
}

/// Codificación de texto de una conexión Telnet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Latin1,
    Cp437,
}

impl Encoding {
    pub const ALL: [(Encoding, &'static str); 3] = [(Encoding::Utf8, "UTF-8"), (Encoding::Latin1, "Latin-1"), (Encoding::Cp437, "CP437")];

    fn as_str(self) -> &'static str {
        match self {
            Encoding::Utf8 => "utf8",
            Encoding::Latin1 => "latin1",
            Encoding::Cp437 => "cp437",
        }
    }

    fn parse(text: &str) -> Self {
        match text {
            "latin1" => Encoding::Latin1,
            "cp437" => Encoding::Cp437,
            _ => Encoding::Utf8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelnetOptions {
    /// Negociar opciones Telnet; apagado, la conexión es TCP simple.
    pub negotiate: bool,
    pub encoding: Encoding,
    /// No avisar de que Telnet no cifra al abrir esta conexión.
    pub quiet: bool,
}

impl Default for TelnetOptions {
    fn default() -> Self {
        Self { negotiate: true, encoding: Encoding::Utf8, quiet: false }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parity {
    None,
    Odd,
    Even,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    None,
    /// XON/XOFF.
    Software,
    /// RTS/CTS.
    Hardware,
}

/// Qué bytes se envían al pulsar Enter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Newline {
    Cr,
    Lf,
    CrLf,
}

impl Newline {
    pub const ALL: [(Newline, &'static str); 3] = [(Newline::Cr, "CR"), (Newline::Lf, "LF"), (Newline::CrLf, "CR LF")];

    pub fn bytes(self) -> &'static [u8] {
        match self {
            Newline::Cr => b"\r",
            Newline::Lf => b"\n",
            Newline::CrLf => b"\r\n",
        }
    }
}

/// Parámetros de una conexión por puerto serie (el puerto va en `Connection::host`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SerialOptions {
    pub baud: u32,
    pub data_bits: u8,
    pub parity: Parity,
    pub stop_bits: u8,
    pub flow: Flow,
    pub newline: Newline,
    pub local_echo: bool,
}

pub const BAUD_RATES: [u32; 8] = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600];

impl Default for SerialOptions {
    fn default() -> Self {
        Self { baud: 115_200, data_bits: 8, parity: Parity::None, stop_bits: 1, flow: Flow::None, newline: Newline::Cr, local_echo: false }
    }
}

impl SerialOptions {
    /// `baudios,bits,paridad,paradas,flujo,salto,eco`, por ejemplo `115200,8,N,1,none,cr,0`.
    pub fn to_text(self) -> String {
        let parity = match self.parity {
            Parity::None => "N",
            Parity::Odd => "O",
            Parity::Even => "E",
        };
        let flow = match self.flow {
            Flow::None => "none",
            Flow::Software => "xonxoff",
            Flow::Hardware => "rtscts",
        };
        let newline = match self.newline {
            Newline::Cr => "cr",
            Newline::Lf => "lf",
            Newline::CrLf => "crlf",
        };
        format!("{},{},{parity},{},{flow},{newline},{}", self.baud, self.data_bits, self.stop_bits, u8::from(self.local_echo))
    }

    /// Lo que no se entiende queda con el valor por defecto.
    pub fn parse(text: &str) -> Self {
        let mut options = Self::default();
        let parts: Vec<&str> = text.split(',').collect();
        if let Some(baud) = parts.first().and_then(|t| t.parse::<u32>().ok()).filter(|b| *b > 0) {
            options.baud = baud;
        }
        if let Some(bits) = parts.get(1).and_then(|t| t.parse::<u8>().ok()).filter(|b| (5..=8).contains(b)) {
            options.data_bits = bits;
        }
        options.parity = match parts.get(2) {
            Some(&"O") => Parity::Odd,
            Some(&"E") => Parity::Even,
            _ => Parity::None,
        };
        if let Some(stop) = parts.get(3).and_then(|t| t.parse::<u8>().ok()).filter(|s| matches!(s, 1 | 2)) {
            options.stop_bits = stop;
        }
        options.flow = match parts.get(4) {
            Some(&"xonxoff") => Flow::Software,
            Some(&"rtscts") => Flow::Hardware,
            _ => Flow::None,
        };
        options.newline = match parts.get(5) {
            Some(&"lf") => Newline::Lf,
            Some(&"crlf") => Newline::CrLf,
            _ => Newline::Cr,
        };
        options.local_echo = parts.get(6) == Some(&"1");
        options
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FtpTls {
    None,
    /// FTPS explícito: conecta en claro y sube a TLS (AUTH TLS).
    Explicit,
    /// FTPS implícito: TLS desde el primer byte (puerto 990).
    Implicit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FtpOptions {
    pub tls: FtpTls,
    pub passive: bool,
    /// Entra como `anonymous`, sin pedir contraseña.
    pub anonymous: bool,
    /// No avisar de que FTP sin cifrar viaja en claro.
    pub quiet: bool,
}

impl Default for FtpOptions {
    fn default() -> Self {
        Self { tls: FtpTls::None, passive: true, anonymous: false, quiet: false }
    }
}

impl FtpOptions {
    fn to_text(self) -> String {
        let tls = match self.tls {
            FtpTls::None => "none",
            FtpTls::Explicit => "explicit",
            FtpTls::Implicit => "implicit",
        };
        format!("ftp,{tls},{},{},{}", u8::from(self.passive), u8::from(self.anonymous), u8::from(self.quiet))
    }

    fn parse(parts: &[&str]) -> Self {
        let flag = |index: usize, default: bool| parts.get(index).map_or(default, |t| *t == "1");
        Self {
            tls: match parts.get(1) {
                Some(&"explicit") => FtpTls::Explicit,
                Some(&"implicit") => FtpTls::Implicit,
                _ => FtpTls::None,
            },
            passive: flag(2, true),
            anonymous: flag(3, false),
            quiet: flag(4, false),
        }
    }
}

/// Conexiones «de archivos»: sin terminal, abren directamente el explorador.
/// El recurso compartido de SMB va en `Connection::init_command` y el dominio en `key_path`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesKind {
    Sftp,
    Ftp(FtpOptions),
    Smb,
}

impl FilesKind {
    fn to_text(self) -> String {
        match self {
            FilesKind::Sftp => "sftp".into(),
            FilesKind::Ftp(options) => options.to_text(),
            FilesKind::Smb => "smb".into(),
        }
    }

    fn parse(text: &str) -> Self {
        let parts: Vec<&str> = text.split(',').collect();
        match parts.first() {
            Some(&"ftp") => FilesKind::Ftp(FtpOptions::parse(&parts)),
            Some(&"smb") => FilesKind::Smb,
            _ => FilesKind::Sftp,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Ssh,
    Telnet(TelnetOptions),
    Serial(SerialOptions),
    Files(FilesKind),
    /// Dispositivo Android por el servidor `adb`: el número de serie (o `ip:puerto`) va en `host`.
    Adb,
    /// Perfil de terminal local: intérprete en `host` (vacío = el del sistema), argumentos en `user`,
    /// directorio inicial en `key_path` y variables de entorno en `Connection::vars`.
    Local,
    /// Motor de contenedores (Docker o Podman). Se llega por la conexión SSH guardada en `jump`, o en este
    /// equipo si no hay; el socket va en `host` (vacío = detectarlo al conectar).
    Engine,
}

impl Protocol {
    /// Columnas `protocol`, `telnet_raw`, `encoding` y `telnet_quiet`.
    fn columns(self) -> (&'static str, bool, &'static str, bool, Option<String>) {
        match self {
            Protocol::Ssh => ("ssh", false, "utf8", false, None),
            Protocol::Telnet(o) => ("telnet", !o.negotiate, o.encoding.as_str(), o.quiet, None),
            Protocol::Serial(o) => ("serial", false, "utf8", false, Some(o.to_text())),
            Protocol::Files(kind) => ("files", false, "utf8", false, Some(kind.to_text())),
            Protocol::Adb => ("adb", false, "utf8", false, None),
            Protocol::Local => ("local", false, "utf8", false, None),
            Protocol::Engine => ("engine", false, "utf8", false, None),
        }
    }

    fn from_columns(protocol: &str, raw: bool, encoding: &str, quiet: bool, serial: Option<&str>) -> Self {
        match protocol {
            "telnet" => Protocol::Telnet(TelnetOptions { negotiate: !raw, encoding: Encoding::parse(encoding), quiet }),
            "serial" => Protocol::Serial(SerialOptions::parse(serial.unwrap_or(""))),
            "files" => Protocol::Files(FilesKind::parse(serial.unwrap_or(""))),
            "adb" => Protocol::Adb,
            "local" => Protocol::Local,
            "engine" => Protocol::Engine,
            _ => Protocol::Ssh,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    pub protocol: Protocol,
    pub id: Option<i64>,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    pub key_path: Option<String>,
    pub init_command: Option<String>,
    /// Conexión guardada por la que se salta para llegar a esta (ProxyJump).
    pub jump: Option<i64>,
    /// Color de identidad (0..6, ver `theme::identity`) para reconocer el servidor de un vistazo.
    pub color: Option<u8>,
    /// Entorno en texto libre, por ejemplo «producción».
    pub env: Option<String>,
    /// Variables de entorno de un perfil local, una por línea con la forma `NOMBRE=valor`.
    pub vars: String,
}

impl Connection {
    /// Solo SSH tiene explorador de archivos, túneles y credenciales.
    pub fn is_ssh(&self) -> bool {
        self.protocol == Protocol::Ssh
    }

    /// Conexión sin terminal: solo explorador de archivos.
    pub fn is_files(&self) -> bool {
        matches!(self.protocol, Protocol::Files(_))
    }

    /// Recurso compartido de una conexión SMB.
    pub fn smb_share(&self) -> &str {
        self.init_command.as_deref().unwrap_or("")
    }

    /// Dominio de una conexión SMB.
    pub fn smb_domain(&self) -> &str {
        self.key_path.as_deref().unwrap_or("")
    }

    /// Nombre del protocolo si lo que escribes viaja en claro (Telnet o FTP sin cifrar).
    pub fn insecure_protocol(&self) -> Option<&'static str> {
        match self.protocol {
            Protocol::Telnet(_) => Some("Telnet"),
            Protocol::Files(FilesKind::Ftp(o)) if o.tls == FtpTls::None => Some("FTP sin cifrar"),
            _ => None,
        }
    }

    pub fn is_adb(&self) -> bool {
        self.protocol == Protocol::Adb
    }

    pub fn is_local(&self) -> bool {
        self.protocol == Protocol::Local
    }

    pub fn is_engine(&self) -> bool {
        self.protocol == Protocol::Engine
    }

    /// Socket fijado a mano de un motor de contenedores; `None` lo detecta al conectar.
    pub fn engine_socket(&self) -> Option<&str> {
        Some(self.host.trim()).filter(|s| !s.is_empty())
    }

    /// Nombre corto del intérprete de un perfil local, o «shell del sistema» si no se eligió uno.
    pub fn local_shell_name(&self) -> String {
        let program = self.host.trim();
        if program.is_empty() {
            return "shell del sistema".to_string();
        }
        let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
        name.strip_suffix(".exe").unwrap_or(name).to_string()
    }

    pub fn is_serial(&self) -> bool {
        matches!(self.protocol, Protocol::Serial(_))
    }

    pub fn is_telnet(&self) -> bool {
        matches!(self.protocol, Protocol::Telnet(_))
    }

    /// Tipo en una palabra, para la lista: «SSH», «SFTP», «ADB»…
    pub fn kind_label(&self) -> &'static str {
        match self.protocol {
            Protocol::Ssh => "SSH",
            Protocol::Telnet(_) => "Telnet",
            Protocol::Serial(_) => "Serie",
            Protocol::Files(FilesKind::Sftp) => "SFTP",
            Protocol::Files(FilesKind::Ftp(_)) => "FTP",
            Protocol::Files(FilesKind::Smb) => "SMB",
            Protocol::Adb => "ADB",
            Protocol::Local => "Local",
            Protocol::Engine => "Contenedores",
        }
    }

    /// A dónde conecta, sin el nombre del protocolo.
    pub fn destination(&self) -> String {
        match self.protocol {
            Protocol::Ssh | Protocol::Files(FilesKind::Sftp) => format!("{}@{}", self.user, self.host),
            Protocol::Telnet(_) => format!("{}:{}", self.host, self.port),
            Protocol::Serial(o) => format!("{} · {}", self.host, o.baud),
            Protocol::Files(FilesKind::Ftp(o)) => format!("{}@{}", if o.anonymous { "anónimo" } else { self.user.as_str() }, self.host),
            Protocol::Files(FilesKind::Smb) => format!("\\\\{}\\{}", self.host, self.smb_share()),
            Protocol::Adb if self.host.is_empty() => "el dispositivo conectado".to_string(),
            Protocol::Adb => self.host.clone(),
            Protocol::Local => self.local_shell_name(),
            Protocol::Engine => self.engine_place(),
        }
    }

    /// Dónde está un motor: su socket si se fijó; si no, si es de este equipo o remoto.
    fn engine_place(&self) -> String {
        match (self.engine_socket(), self.jump) {
            (Some(socket), _) => socket.to_string(),
            (None, Some(_)) => "servidor SSH".to_string(),
            (None, None) => "este equipo".to_string(),
        }
    }

    /// Destino para mostrar: `usuario@host` en SSH y `telnet · host:puerto` en Telnet.
    pub fn target(&self) -> String {
        match self.protocol {
            Protocol::Ssh => format!("{}@{}", self.user, self.host),
            Protocol::Telnet(_) => format!("telnet · {}:{}", self.host, self.port),
            Protocol::Serial(o) => format!("serie · {} · {}", self.host, o.baud),
            Protocol::Adb if self.host.is_empty() => "adb · el dispositivo conectado".to_string(),
            Protocol::Adb => format!("adb · {}", self.host),
            Protocol::Local => format!("local · {}", self.local_shell_name()),
            Protocol::Engine => format!("contenedores · {}", self.engine_place()),
            Protocol::Files(FilesKind::Sftp) => format!("sftp · {}@{}", self.user, self.host),
            Protocol::Files(FilesKind::Ftp(o)) => {
                let who = if o.anonymous { "anónimo" } else { self.user.as_str() };
                format!("ftp · {who}@{}", self.host)
            }
            Protocol::Files(FilesKind::Smb) => format!("smb · \\\\{}\\{}", self.host, self.smb_share()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snippet {
    pub id: Option<i64>,
    pub title: String,
    pub tag: String,
    pub body: String,
}

impl Snippet {
    /// ¿Coincide con la búsqueda (sin distinguir mayúsculas) en título, etiqueta o contenido?
    pub fn matches(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        query.is_empty()
            || [&self.title, &self.tag, &self.body].iter().any(|field| field.to_lowercase().contains(&query))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardKind {
    /// `-L`: escucha en este equipo y reenvía al destino a través del servidor.
    Local,
    /// `-R`: el servidor escucha y reenvía a un destino alcanzable desde este equipo.
    Remote,
    /// `-D`: proxy SOCKS5 local; cada conexión elige su destino y sale por el servidor.
    Dynamic,
}

impl ForwardKind {
    fn as_str(self) -> &'static str {
        match self {
            ForwardKind::Local => "local",
            ForwardKind::Remote => "remote",
            ForwardKind::Dynamic => "dynamic",
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "local" => Ok(ForwardKind::Local),
            "remote" => Ok(ForwardKind::Remote),
            "dynamic" => Ok(ForwardKind::Dynamic),
            other => bail!("tipo de túnel desconocido: {other}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    pub kind: ForwardKind,
    pub bind_host: String,
    pub bind_port: u16,
    pub dest_host: String,
    pub dest_port: u16,
}

impl Forward {
    /// Texto corto para la interfaz, por ejemplo `L 8080 → db:5432`.
    pub fn summary(&self) -> String {
        match self.kind {
            ForwardKind::Local => format!("L {} → {}:{}", self.bind_port, self.dest_host, self.dest_port),
            ForwardKind::Remote => format!("R {} → {}:{}", self.bind_port, self.dest_host, self.dest_port),
            ForwardKind::Dynamic => format!("D {} (SOCKS)", self.bind_port),
        }
    }
}

/// Qué abre cada pestaña al restaurar la sesión.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabKind {
    Local,
    Connection(i64),
    Explorer(i64),
    /// Administrador de contenedores y terminales dentro de uno: no se guardan en la sesión.
    Containers,
    Container,
    /// Página de ajustes: tampoco se restaura.
    Settings,
}

/// Una pestaña tal como se guarda: su tipo y, en el explorador, las dos rutas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedTab {
    pub kind: TabKind,
    pub local_path: Option<String>,
    pub remote_path: Option<String>,
}

impl SavedTab {
    pub fn plain(kind: TabKind) -> Self {
        Self { kind, local_path: None, remote_path: None }
    }
}

pub struct Store {
    db: Db,
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).with_context(|| format!("protegiendo {}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}

/// Crea el archivo vacío con modo 0600 si no existe; si existe, le quita el acceso a otros usuarios.
fn restrict_file(path: &Path) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path).with_context(|| format!("abriendo {}", path.display()))?;
    restrict(path, 0o600)
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            let created = !parent.exists();
            std::fs::create_dir_all(parent).with_context(|| format!("creando {}", parent.display()))?;
            let own_dir = Self::default_path().ok().and_then(|p| p.parent().map(Path::to_path_buf));
            if created || own_dir.as_deref() == Some(parent) {
                restrict(parent, 0o700)?;
            }
        }
        // SQLite crea `-wal` y `-shm` con los permisos de la base: se fijan antes de abrirla.
        restrict_file(path)?;
        Self::init(Db::open(path).with_context(|| format!("abriendo {}", path.display()))?)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::init(Db::open_in_memory()?)
    }

    pub fn default_path() -> anyhow::Result<std::path::PathBuf> {
        // El nombre del directorio y del archivo se mantienen para no perder datos existentes.
        let dirs = directories::ProjectDirs::from("dev", "omniterm", "omniterm")
            .context("no se pudo determinar el directorio de datos")?;
        Ok(dirs.data_dir().join("omniterm.db"))
    }

    fn init(db: Db) -> anyhow::Result<Self> {
        db.pragma_update(None, "foreign_keys", true)?;
        let mut store = Self { db };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> anyhow::Result<()> {
        let current = self.db.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))? as usize;
        if current > MIGRATIONS.len() {
            bail!("la base de datos es más nueva que esta versión de omni-term");
        }
        for (index, sql) in MIGRATIONS.iter().enumerate().skip(current) {
            let tx = self.db.transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", (index + 1) as i64)?;
            tx.commit()?;
        }
        Ok(())
    }

    pub fn list_connections(&self) -> anyhow::Result<Vec<Connection>> {
        let mut statement = self.db.prepare(
            "SELECT id, name, host, port, user, auth, key_path, init_command, jump_id, color, env,
                    protocol, telnet_raw, encoding, telnet_quiet, serial_opts
             FROM connections ORDER BY name COLLATE NOCASE",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u16>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<u8>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, bool>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, bool>(14)?,
                row.get::<_, Option<String>>(15)?,
            ))
        })?;
        rows.map(|row| {
            let (id, name, host, port, user, auth, key_path, init_command, jump, color, env, protocol, raw, encoding, quiet, serial) = row?;
            let protocol_value = Protocol::from_columns(&protocol, raw, &encoding, quiet, serial.as_deref());
            let vars = if protocol_value == Protocol::Local { serial.clone().unwrap_or_default() } else { String::new() };
            Ok(Connection {
                protocol: protocol_value,
                id: Some(id),
                name,
                host,
                port,
                user,
                auth: Auth::parse(&auth)?,
                key_path,
                init_command,
                jump,
                color,
                env,
                vars,
            })
        })
        .collect()
    }

    /// Inserta o actualiza y devuelve el id.
    pub fn save_connection(&self, connection: &Connection) -> anyhow::Result<i64> {
        let mut columns = connection.protocol.columns();
        if connection.protocol == Protocol::Local {
            columns.4 = Some(connection.vars.clone());
        }
        match connection.id {
            Some(id) => {
                self.db.execute(
                    "UPDATE connections SET name=?1, host=?2, port=?3, user=?4, auth=?5, key_path=?6, init_command=?7, jump_id=?8,
                     color=?9, env=?10, protocol=?11, telnet_raw=?12, encoding=?13, telnet_quiet=?14, serial_opts=?15 WHERE id=?16",
                    params![
                        connection.name,
                        connection.host,
                        connection.port,
                        connection.user,
                        connection.auth.as_str(),
                        connection.key_path,
                        connection.init_command,
                        connection.jump,
                        connection.color,
                        connection.env,
                        columns.0,
                        columns.1,
                        columns.2,
                        columns.3,
                        columns.4,
                        id
                    ],
                )?;
                Ok(id)
            }
            None => {
                self.db.execute(
                    "INSERT INTO connections (name, host, port, user, auth, key_path, init_command, jump_id, color, env,
                                              protocol, telnet_raw, encoding, telnet_quiet, serial_opts)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        connection.name,
                        connection.host,
                        connection.port,
                        connection.user,
                        connection.auth.as_str(),
                        connection.key_path,
                        connection.init_command,
                        connection.jump,
                        connection.color,
                        connection.env.clone(),
                        columns.0,
                        columns.1,
                        columns.2,
                        columns.3,
                        columns.4
                    ],
                )?;
                Ok(self.db.last_insert_rowid())
            }
        }
    }

    /// Vuelve a insertar una conexión borrada, con su mismo id (para «Deshacer»).
    pub fn restore_connection(&self, connection: &Connection) -> anyhow::Result<()> {
        let id = connection.id.context("la conexión no tiene id")?;
        let mut columns = connection.protocol.columns();
        if connection.protocol == Protocol::Local {
            columns.4 = Some(connection.vars.clone());
        }
        self.db.execute(
            "INSERT INTO connections (id, name, host, port, user, auth, key_path, init_command, jump_id, color, env,
                                      protocol, telnet_raw, encoding, telnet_quiet, serial_opts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                id,
                connection.name,
                connection.host,
                connection.port,
                connection.user,
                connection.auth.as_str(),
                connection.key_path,
                connection.init_command,
                connection.jump,
                connection.color,
                connection.env,
                columns.0,
                columns.1,
                columns.2,
                columns.3,
                columns.4
            ],
        )?;
        Ok(())
    }

    /// Reasigna el salto de una conexión (para restaurar las que dependían de una borrada).
    pub fn set_jump(&self, id: i64, jump: Option<i64>) -> anyhow::Result<()> {
        self.db.execute("UPDATE connections SET jump_id=?1 WHERE id=?2", params![jump, id])?;
        Ok(())
    }

    pub fn restore_snippet(&self, snippet: &Snippet) -> anyhow::Result<()> {
        let id = snippet.id.context("el snippet no tiene id")?;
        self.db.execute(
            "INSERT INTO snippets (id, title, tag, body) VALUES (?1, ?2, ?3, ?4)",
            params![id, snippet.title, snippet.tag, snippet.body],
        )?;
        Ok(())
    }

    pub fn delete_connection(&self, id: i64) -> anyhow::Result<()> {
        self.db.execute("DELETE FROM connections WHERE id=?1", [id])?;
        Ok(())
    }

    /// Túneles de todas las conexiones, en el orden en que se definieron.
    pub fn all_forwards(&self) -> anyhow::Result<std::collections::HashMap<i64, Vec<Forward>>> {
        let mut statement = self.db.prepare(
            "SELECT connection_id, kind, bind_host, bind_port, dest_host, dest_port
             FROM forwards ORDER BY connection_id, position",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u16>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, u16>(5)?,
            ))
        })?;
        let mut all: std::collections::HashMap<i64, Vec<Forward>> = Default::default();
        for row in rows {
            let (connection_id, kind, bind_host, bind_port, dest_host, dest_port) = row?;
            all.entry(connection_id).or_default().push(Forward {
                kind: ForwardKind::parse(&kind)?,
                bind_host,
                bind_port,
                dest_host,
                dest_port,
            });
        }
        Ok(all)
    }

    #[cfg(test)]
    pub fn list_forwards(&self, connection_id: i64) -> anyhow::Result<Vec<Forward>> {
        Ok(self.all_forwards()?.remove(&connection_id).unwrap_or_default())
    }

    pub fn replace_forwards(&mut self, connection_id: i64, forwards: &[Forward]) -> anyhow::Result<()> {
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM forwards WHERE connection_id=?1", [connection_id])?;
        for (position, forward) in forwards.iter().enumerate() {
            tx.execute(
                "INSERT INTO forwards (connection_id, position, kind, bind_host, bind_port, dest_host, dest_port)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    connection_id,
                    position as i64,
                    forward.kind.as_str(),
                    forward.bind_host,
                    forward.bind_port,
                    forward.dest_host,
                    forward.dest_port
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_snippets(&self) -> anyhow::Result<Vec<Snippet>> {
        let mut statement =
            self.db.prepare("SELECT id, title, tag, body FROM snippets ORDER BY title COLLATE NOCASE, id")?;
        let rows = statement.query_map([], |row| {
            Ok(Snippet { id: Some(row.get(0)?), title: row.get(1)?, tag: row.get(2)?, body: row.get(3)? })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn save_snippet(&self, snippet: &Snippet) -> anyhow::Result<i64> {
        match snippet.id {
            Some(id) => {
                self.db.execute(
                    "UPDATE snippets SET title=?1, tag=?2, body=?3 WHERE id=?4",
                    params![snippet.title, snippet.tag, snippet.body, id],
                )?;
                Ok(id)
            }
            None => {
                self.db.execute(
                    "INSERT INTO snippets (title, tag, body) VALUES (?1, ?2, ?3)",
                    params![snippet.title, snippet.tag, snippet.body],
                )?;
                Ok(self.db.last_insert_rowid())
            }
        }
    }

    pub fn delete_snippet(&self, id: i64) -> anyhow::Result<()> {
        self.db.execute("DELETE FROM snippets WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn save_layout(&mut self, tabs: &[SavedTab], active: usize) -> anyhow::Result<()> {
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM layout_tabs", [])?;
        for (position, tab) in tabs.iter().enumerate() {
            let (kind, connection_id) = match tab.kind {
                TabKind::Local | TabKind::Containers | TabKind::Container | TabKind::Settings => ("local", None),
                TabKind::Connection(id) => ("connection", Some(id)),
                TabKind::Explorer(id) => ("explorer", Some(id)),
            };
            tx.execute(
                "INSERT INTO layout_tabs (position, connection_id, kind, local_path, remote_path)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![position as i64, connection_id, kind, tab.local_path, tab.remote_path],
            )?;
        }
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('active_tab', ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [active.to_string().into_bytes()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Pestañas guardadas y la activa. Las conexiones que ya no existen se descartan.
    pub fn load_layout(&self) -> anyhow::Result<(Vec<SavedTab>, usize)> {
        let mut statement = self.db.prepare(
            "SELECT t.connection_id, c.id, t.kind, t.local_path, t.remote_path FROM layout_tabs t
             LEFT JOIN connections c ON c.id = t.connection_id
             ORDER BY t.position",
        )?;
        let tabs = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .filter_map(|row| {
                let (wanted, existing, kind, local_path, remote_path) = match row {
                    Ok(row) => row,
                    Err(error) => return Some(Err(error)),
                };
                let kind = match (wanted, existing, kind.as_str()) {
                    (None, _, _) => TabKind::Local,
                    (Some(_), None, _) => return None,
                    (Some(_), Some(id), "explorer") => TabKind::Explorer(id),
                    (Some(_), Some(id), _) => TabKind::Connection(id),
                };
                Some(Ok(SavedTab { kind, local_path, remote_path }))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let active: Option<Vec<u8>> =
            self.db.query_row("SELECT value FROM meta WHERE key='active_tab'", [], |row| row.get(0)).optional()?;
        let active = active
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| text.parse::<usize>().ok())
            .unwrap_or(0);
        Ok((tabs, active))
    }

    pub fn meta(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.db.query_row("SELECT value FROM meta WHERE key=?1", [key], |row| row.get(0)).optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn put_secret(&self, account: &str, nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT INTO secrets (account, nonce, ciphertext) VALUES (?1, ?2, ?3)
             ON CONFLICT(account) DO UPDATE SET nonce=excluded.nonce, ciphertext=excluded.ciphertext",
            params![account, nonce, ciphertext],
        )?;
        Ok(())
    }

    pub fn get_secret(&self, account: &str) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .db
            .query_row("SELECT nonce, ciphertext FROM secrets WHERE account=?1", [account], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?)
    }

    pub fn delete_secret(&self, account: &str) -> anyhow::Result<()> {
        self.db.execute("DELETE FROM secrets WHERE account=?1", [account])?;
        Ok(())
    }

    pub fn secret_count(&self) -> anyhow::Result<usize> {
        Ok(self.db.query_row("SELECT COUNT(*) FROM secrets", [], |row| row.get::<_, i64>(0))? as usize)
    }

    pub fn clear_secrets(&self) -> anyhow::Result<()> {
        self.db.execute("DELETE FROM secrets", [])?;
        self.db.execute("DELETE FROM meta WHERE key IN ('kdf_salt', 'kdf_check')", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str) -> Connection {
        Connection {
            id: None,
            protocol: Protocol::Ssh,
            name: name.into(),
            host: "example.com".into(),
            port: 22,
            user: "root".into(),
            auth: Auth::Key,
            key_path: Some("/home/u/.ssh/id_ed25519".into()),
            init_command: None,
            jump: None,
            color: None,
            env: None,
            vars: String::new(),
        }
    }

    #[test]
    fn serial_options_round_trip_through_text_and_the_database() {
        let options = SerialOptions { baud: 9600, data_bits: 7, parity: Parity::Even, stop_bits: 2, flow: Flow::Hardware, newline: Newline::CrLf, local_echo: true };
        assert_eq!(options.to_text(), "9600,7,E,2,rtscts,crlf,1");
        assert_eq!(SerialOptions::parse(&options.to_text()), options);
        assert_eq!(SerialOptions::parse("basura"), SerialOptions::default());
        assert_eq!(SerialOptions::parse("57600,9,X,3,zzz,qq,0").data_bits, 8);

        let store = Store::open_in_memory().unwrap();
        let mut serial = sample("consola");
        serial.host = "/dev/ttyUSB0".into();
        serial.port = 0;
        serial.protocol = Protocol::Serial(options);
        let id = store.save_connection(&serial).unwrap();
        let loaded = store.list_connections().unwrap().into_iter().find(|c| c.id == Some(id)).unwrap();
        assert_eq!(loaded.protocol, serial.protocol);
        assert_eq!(loaded.target(), "serie · /dev/ttyUSB0 · 9600");
        assert!(loaded.is_serial() && !loaded.is_ssh());
    }

    #[test]
    fn telnet_options_round_trip_and_ssh_is_the_default() {
        let store = Store::open_in_memory().unwrap();
        let mut telnet = sample("router");
        telnet.port = 23;
        telnet.protocol = Protocol::Telnet(TelnetOptions { negotiate: false, encoding: Encoding::Cp437, quiet: true });
        let id = store.save_connection(&telnet).unwrap();
        store.save_connection(&sample("web")).unwrap();

        let listed = store.list_connections().unwrap();
        let loaded = listed.iter().find(|c| c.id == Some(id)).unwrap();
        assert_eq!(loaded.protocol, telnet.protocol);
        assert!(loaded.is_telnet());
        assert_eq!(loaded.target(), "telnet · example.com:23");
        assert_eq!(listed.iter().find(|c| c.name == "web").unwrap().protocol, Protocol::Ssh);

        store.delete_connection(id).unwrap();
        let mut restored = telnet.clone();
        restored.id = Some(id);
        store.restore_connection(&restored).unwrap();
        assert_eq!(store.list_connections().unwrap().iter().find(|c| c.id == Some(id)).unwrap().protocol, telnet.protocol);
    }

    #[test]
    fn saves_updates_and_lists_connections_sorted() {
        let store = Store::open_in_memory().unwrap();
        let b = store.save_connection(&sample("beta")).unwrap();
        store.save_connection(&sample("Alpha")).unwrap();

        let mut updated = store.list_connections().unwrap().into_iter().find(|c| c.id == Some(b)).unwrap();
        updated.host = "other.test".into();
        updated.port = 2222;
        store.save_connection(&updated).unwrap();

        let all = store.list_connections().unwrap();
        assert_eq!(all.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["Alpha", "beta"]);
        assert_eq!(all[1].host, "other.test");
        assert_eq!(all[1].port, 2222);
    }

    #[test]
    fn a_deleted_connection_and_snippet_can_be_restored_with_the_same_id() {
        let mut store = Store::open_in_memory().unwrap();
        let bastion = store.save_connection(&sample("bastion")).unwrap();
        let mut inner = sample("interno");
        inner.jump = Some(bastion);
        inner.color = Some(2);
        let inner_id = store.save_connection(&inner).unwrap();
        let web = Forward { kind: ForwardKind::Local, bind_host: "127.0.0.1".into(), bind_port: 8080, dest_host: "web".into(), dest_port: 80 };
        store.replace_forwards(bastion, &[web.clone()]).unwrap();
        let snippet_id = store.save_snippet(&Snippet { id: None, title: "uno".into(), tag: String::new(), body: "ls".into() }).unwrap();

        let saved = store.list_connections().unwrap().into_iter().find(|c| c.id == Some(bastion)).unwrap();
        let saved_snippet = store.list_snippets().unwrap().remove(0);
        store.delete_connection(bastion).unwrap();
        store.delete_snippet(snippet_id).unwrap();
        assert!(store.list_snippets().unwrap().is_empty());
        assert_eq!(store.list_connections().unwrap().len(), 1);

        store.restore_connection(&saved).unwrap();
        store.replace_forwards(bastion, &[web.clone()]).unwrap();
        store.set_jump(inner_id, Some(bastion)).unwrap();
        store.restore_snippet(&saved_snippet).unwrap();

        let restored = store.list_connections().unwrap();
        assert_eq!(restored.iter().find(|c| c.id == Some(bastion)), Some(&saved));
        assert_eq!(restored.iter().find(|c| c.id == Some(inner_id)).unwrap().jump, Some(bastion));
        assert_eq!(store.list_forwards(bastion).unwrap(), vec![web]);
        assert_eq!(store.list_snippets().unwrap(), vec![saved_snippet]);
    }

    #[test]
    fn identity_color_and_environment_round_trip() {
        let store = Store::open_in_memory().unwrap();
        let mut production = sample("prod-db");
        production.color = Some(0);
        production.env = Some("producción".into());
        let id = store.save_connection(&production).unwrap();
        let loaded = store.list_connections().unwrap().into_iter().find(|c| c.id == Some(id)).unwrap();
        assert_eq!((loaded.color, loaded.env.as_deref()), (Some(0), Some("producción")));

        let mut cleared = loaded;
        cleared.color = None;
        cleared.env = None;
        store.save_connection(&cleared).unwrap();
        let again = store.list_connections().unwrap().into_iter().find(|c| c.id == Some(id)).unwrap();
        assert_eq!((again.color, again.env), (None, None));
    }

    #[test]
    fn jump_host_is_stored_and_cleared_when_the_jump_is_deleted() {
        let store = Store::open_in_memory().unwrap();
        let bastion = store.save_connection(&sample("bastion")).unwrap();
        let mut inner = sample("interno");
        inner.jump = Some(bastion);
        inner.auth = Auth::Interactive;
        let inner_id = store.save_connection(&inner).unwrap();

        let loaded = store.list_connections().unwrap().into_iter().find(|c| c.id == Some(inner_id)).unwrap();
        assert_eq!(loaded.jump, Some(bastion));
        assert_eq!(loaded.auth, Auth::Interactive);

        store.delete_connection(bastion).unwrap();
        let loaded = store.list_connections().unwrap().into_iter().find(|c| c.id == Some(inner_id)).unwrap();
        assert_eq!(loaded.jump, None);
    }

    #[test]
    fn layout_round_trips_and_drops_deleted_connections() {
        let mut store = Store::open_in_memory().unwrap();
        let a = store.save_connection(&sample("a")).unwrap();
        let b = store.save_connection(&sample("b")).unwrap();
        let explorer = SavedTab {
            kind: TabKind::Explorer(a),
            local_path: Some("/home/u/docs".into()),
            remote_path: Some("/srv/www".into()),
        };
        let saved = vec![
            SavedTab::plain(TabKind::Local),
            SavedTab::plain(TabKind::Connection(a)),
            explorer.clone(),
            SavedTab::plain(TabKind::Connection(b)),
        ];
        store.save_layout(&saved, 2).unwrap();

        assert_eq!(store.load_layout().unwrap(), (saved, 2));

        store.delete_connection(a).unwrap();
        assert_eq!(
            store.load_layout().unwrap().0,
            vec![SavedTab::plain(TabKind::Local), SavedTab::plain(TabKind::Connection(b))]
        );
    }

    #[test]
    fn forwards_are_kept_in_order_per_connection_and_cascade_on_delete() {
        let mut store = Store::open_in_memory().unwrap();
        let a = store.save_connection(&sample("a")).unwrap();
        let b = store.save_connection(&sample("b")).unwrap();
        let web = Forward { kind: ForwardKind::Local, bind_host: "127.0.0.1".into(), bind_port: 8080, dest_host: "web".into(), dest_port: 80 };
        let db = Forward { kind: ForwardKind::Remote, bind_host: "127.0.0.1".into(), bind_port: 5433, dest_host: "localhost".into(), dest_port: 5432 };
        store.replace_forwards(a, &[web.clone(), db.clone()]).unwrap();
        store.replace_forwards(b, &[db.clone()]).unwrap();

        assert_eq!(store.list_forwards(a).unwrap(), vec![web.clone(), db.clone()]);
        assert_eq!(web.summary(), "L 8080 → web:80");
        let socks = Forward { kind: ForwardKind::Dynamic, bind_host: "127.0.0.1".into(), bind_port: 1080, dest_host: String::new(), dest_port: 0 };
        assert_eq!(socks.summary(), "D 1080 (SOCKS)");
        store.replace_forwards(b, &[socks.clone()]).unwrap();
        assert_eq!(store.list_forwards(b).unwrap(), vec![socks]);
        store.replace_forwards(b, &[db.clone()]).unwrap();

        store.replace_forwards(a, &[db.clone()]).unwrap();
        assert_eq!(store.list_forwards(a).unwrap(), vec![db.clone()]);

        store.delete_connection(b).unwrap();
        assert!(store.all_forwards().unwrap().get(&b).is_none());
        assert_eq!(store.list_forwards(a).unwrap().len(), 1);
    }

    #[test]
    fn snippets_roundtrip_update_delete_and_search() {
        let store = Store::open_in_memory().unwrap();
        let id = store
            .save_snippet(&Snippet { id: None, title: "Reiniciar nginx".into(), tag: "ops".into(), body: "sudo systemctl restart nginx".into() })
            .unwrap();
        store
            .save_snippet(&Snippet { id: None, title: "Espacio en disco".into(), tag: String::new(), body: "df -h\ndu -sh *".into() })
            .unwrap();

        let all = store.list_snippets().unwrap();
        assert_eq!(all.iter().map(|s| s.title.as_str()).collect::<Vec<_>>(), ["Espacio en disco", "Reiniciar nginx"]);

        let mut edited = all.iter().find(|s| s.id == Some(id)).unwrap().clone();
        edited.body = "sudo systemctl reload nginx".into();
        store.save_snippet(&edited).unwrap();
        let reloaded = store.list_snippets().unwrap();
        assert!(reloaded.iter().any(|s| s.body.ends_with("reload nginx")));

        assert!(edited.matches("NGINX"));
        assert!(edited.matches("ops"));
        assert!(edited.matches("reload"));
        assert!(edited.matches("  "));
        assert!(!edited.matches("postgres"));

        store.delete_snippet(id).unwrap();
        assert_eq!(store.list_snippets().unwrap().len(), 1);
    }

    #[test]
    fn empty_database_has_empty_layout() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.load_layout().unwrap(), (vec![], 0));
    }

    #[test]
    fn upgrades_a_database_created_before_the_layout_columns() {
        // Una base de datos como la de la versión con snippets: las tres primeras migraciones.
        let dir = std::env::temp_dir().join(format!("omniterm-upgrade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("old.db");
        {
            let db = Db::open(&path).unwrap();
            for sql in &MIGRATIONS[..3] {
                db.execute_batch(sql).unwrap();
            }
            db.pragma_update(None, "user_version", 3_i64).unwrap();
            db.execute("INSERT INTO snippets (title, tag, body) VALUES ('viejo', '', 'ls')", []).unwrap();
        }

        let mut store = Store::open(&path).unwrap();
        assert_eq!(store.list_snippets().unwrap().len(), 1);
        store.save_layout(&[SavedTab::plain(TabKind::Local)], 0).unwrap();
        assert_eq!(store.load_layout().unwrap().0, vec![SavedTab::plain(TabKind::Local)]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn migrations_are_idempotent_on_reopen() {
        let dir = std::env::temp_dir().join(format!("omniterm-test-{}", std::process::id()));
        let path = dir.join("db.sqlite");
        {
            let store = Store::open(&path).unwrap();
            store.save_connection(&sample("kept")).unwrap();
        }
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.list_connections().unwrap().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_local_profile_keeps_its_fields_and_variables() {
        let store = Store::open_in_memory().unwrap();
        let mut profile = sample("dev");
        profile.protocol = Protocol::Local;
        profile.host = "/bin/zsh".into();
        profile.user = "-l".into();
        profile.key_path = Some("~/proyectos".into());
        profile.init_command = Some("ls".into());
        profile.auth = Auth::Agent;
        profile.vars = "A=1\nB=dos".into();
        let id = store.save_connection(&profile).unwrap();
        let mut ssh = sample("web");
        ssh.vars = String::new();
        store.save_connection(&ssh).unwrap();

        let loaded = store.list_connections().unwrap();
        let back = loaded.iter().find(|c| c.id == Some(id)).unwrap();
        assert_eq!(back.protocol, Protocol::Local);
        assert_eq!((back.host.as_str(), back.user.as_str(), back.vars.as_str()), ("/bin/zsh", "-l", "A=1\nB=dos"));
        assert_eq!(back.key_path.as_deref(), Some("~/proyectos"));
        assert_eq!(back.local_shell_name(), "zsh");
        assert_eq!(back.target(), "local · zsh");
        assert!(loaded.iter().find(|c| c.name == "web").unwrap().vars.is_empty());
    }

    #[test]
    fn an_engine_keeps_its_ssh_connection_and_socket() {
        let store = Store::open_in_memory().unwrap();
        let server = store.save_connection(&sample("prod")).unwrap();
        let mut remote = sample("prod · contenedores");
        remote.protocol = Protocol::Engine;
        remote.host = String::new();
        remote.jump = Some(server);
        let remote = store.save_connection(&remote).unwrap();
        let mut local = sample("podman");
        local.protocol = Protocol::Engine;
        local.host = "/run/user/1000/podman/podman.sock".into();
        local.jump = None;
        let local = store.save_connection(&local).unwrap();

        let loaded = store.list_connections().unwrap();
        let remote = loaded.iter().find(|c| c.id == Some(remote)).unwrap();
        assert!(remote.is_engine());
        assert_eq!((remote.jump, remote.engine_socket()), (Some(server), None));
        assert_eq!(remote.target(), "contenedores · servidor SSH");
        let local = loaded.iter().find(|c| c.id == Some(local)).unwrap();
        assert_eq!((local.jump, local.engine_socket()), (None, Some("/run/user/1000/podman/podman.sock")));
    }

    #[test]
    fn secrets_are_upserted_and_cleared() {
        let store = Store::open_in_memory().unwrap();
        store.put_secret("conn:1", b"n1", b"c1").unwrap();
        store.put_secret("conn:1", b"n2", b"c2").unwrap();
        assert_eq!(store.get_secret("conn:1").unwrap(), Some((b"n2".to_vec(), b"c2".to_vec())));
        store.set_meta("kdf_salt", b"salt").unwrap();
        store.clear_secrets().unwrap();
        assert_eq!(store.get_secret("conn:1").unwrap(), None);
        assert_eq!(store.meta("kdf_salt").unwrap(), None);
    }

    #[test]
    fn files_connections_round_trip() {
        let store = Store::open_in_memory().unwrap();
        let kinds = [
            FilesKind::Sftp,
            FilesKind::Smb,
            FilesKind::Ftp(FtpOptions { tls: FtpTls::Implicit, passive: false, anonymous: true, quiet: true }),
        ];
        for (n, kind) in kinds.into_iter().enumerate() {
            let mut c = sample(&format!("files{n}"));
            c.protocol = Protocol::Files(kind);
            store.save_connection(&c).unwrap();
        }
        let loaded = store.list_connections().unwrap();
        for kind in kinds {
            assert!(loaded.iter().any(|c| c.protocol == Protocol::Files(kind) && c.is_files()));
        }
    }

    #[test]
    fn only_plain_ftp_and_telnet_are_insecure() {
        let mut c = sample("x");
        c.protocol = Protocol::Files(FilesKind::Ftp(FtpOptions::default()));
        assert_eq!(c.insecure_protocol(), Some("FTP sin cifrar"));
        c.protocol = Protocol::Files(FilesKind::Ftp(FtpOptions { tls: FtpTls::Explicit, ..FtpOptions::default() }));
        assert_eq!(c.insecure_protocol(), None);
        c.protocol = Protocol::Files(FilesKind::Smb);
        assert_eq!(c.insecure_protocol(), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_database_and_its_folder_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("omniterm-perm-{}", std::process::id())).join("data");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
        let path = dir.join("omniterm.db");
        let store = Store::open(&path).unwrap();
        store.save_connection(&sample("x")).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o600);
        for suffix in ["-wal", "-shm"] {
            let side = dir.join(format!("omniterm.db{suffix}"));
            if side.exists() {
                assert_eq!(mode(&side) & 0o077, 0, "{}", side.display());
            }
        }
        drop(store);

        // Una base creada antes con permisos abiertos se corrige al abrirla.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        Store::open(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        std::fs::remove_dir_all(dir.parent().unwrap()).ok();
    }
}
