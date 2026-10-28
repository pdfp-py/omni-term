//! Docker y Podman: cliente propio de la API del motor por su socket Unix o, en Windows, su tubería con nombre.
//!
//! Solo lo necesario para un administrador pequeño: listar contenedores (también los apagados),
//! iniciar, detener, reiniciar y abrir un shell (`exec` con tty).

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use crate::connect::ssh::SshLink;
use crate::terminal::term::{Backend, Feed};

const TIMEOUT: Duration = Duration::from_secs(10);
/// Detener espera hasta 10 s a que el contenedor termine antes de matarlo.
const ACTION_TIMEOUT: Duration = Duration::from_secs(40);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Docker,
    Podman,
}

impl Engine {
    pub fn name(self) -> &'static str {
        match self {
            Engine::Docker => "Docker",
            Engine::Podman => "Podman",
        }
    }
}

/// Un motor y el socket por el que se le habla: en este equipo (en Windows, una tubería con nombre)
/// o en un servidor, a través de una sesión SSH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub engine: Engine,
    pub socket: PathBuf,
    pub via: Via,
}

impl Endpoint {
    pub fn local(engine: Engine, socket: impl Into<PathBuf>) -> Self {
        Self { engine, socket: socket.into(), via: Via::Local }
    }

    /// Un socket elegido a mano; el motor se deduce de su ruta.
    pub fn fixed(socket: &str, via: Via) -> Self {
        let engine = if socket.to_lowercase().contains("podman") { Engine::Podman } else { Engine::Docker };
        Self { engine, socket: socket.into(), via }
    }
}

/// Por dónde se llega al socket.
#[derive(Clone)]
pub enum Via {
    Local,
    Ssh(Arc<SshLink>),
}

impl std::fmt::Debug for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Via::Local => f.write_str("Local"),
            Via::Ssh(link) => write!(f, "Ssh({})", link.name()),
        }
    }
}

/// Dos `Via::Ssh` son la misma solo si comparten la sesión.
impl PartialEq for Via {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Via::Local, Via::Local) => true,
            (Via::Ssh(a), Via::Ssh(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl Eq for Via {}

/// Comprueba en el servidor los sockets habituales de Docker y Podman (de sistema y rootless) y si se
/// pueden usar. Por el túnel, un socket inexistente y uno sin permiso dan el mismo error genérico.
const REMOTE_PROBE: &str = r#"rt="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"; for s in "${DOCKER_HOST#unix://}" /var/run/docker.sock "$rt/docker.sock" /run/podman/podman.sock "$rt/podman/podman.sock"; do [ -S "$s" ] || continue; if [ -r "$s" ] && [ -w "$s" ]; then echo "ok $s"; else echo "denied $s"; fi; done"#;

/// Sockets utilizables y sin permiso de la salida de `REMOTE_PROBE`, sin repetir.
fn parse_probe(output: &str) -> (Vec<String>, Vec<String>) {
    let (mut usable, mut denied) = (Vec::<String>::new(), Vec::<String>::new());
    for line in output.lines() {
        let (list, path) = match line.split_once(' ') {
            Some(("ok", path)) => (&mut usable, path),
            Some(("denied", path)) => (&mut denied, path),
            _ => continue,
        };
        if !list.iter().any(|p| p == path) {
            list.push(path.to_string());
        }
    }
    (usable, denied)
}

/// Motores de un servidor, por SSH. Sin ninguno utilizable pero alguno sin permiso, explica cómo darlo.
pub async fn detect_remote(link: &Arc<SshLink>) -> anyhow::Result<Vec<Endpoint>> {
    let session = link.session().await?;
    let output = crate::connect::ssh::run_command(&session, REMOTE_PROBE).await?;
    let (usable, denied) = parse_probe(&output);
    if usable.is_empty() && !denied.is_empty() {
        bail!(
            "Tu usuario no tiene permiso sobre {} en {}. Añádelo al grupo «docker»:\n  sudo usermod -aG docker $USER\nY vuelve a conectar.",
            denied.join(", "),
            link.name()
        );
    }
    Ok(usable.iter().map(|socket| Endpoint::fixed(socket, Via::Ssh(link.clone()))).collect())
}

#[cfg(windows)]
const PIPES: &str = r"\\.\pipe\";

/// Motores con tubería en este equipo: Docker Desktop (`DOCKER_HOST` o `docker_engine`) y las máquinas de Podman.
/// Las tuberías se buscan listando `\\.\pipe\`: abrirlas para comprobarlas ocuparía una conexión del motor.
#[cfg(windows)]
pub fn detect_endpoints() -> Vec<Endpoint> {
    let pipes: Vec<String> = std::fs::read_dir(PIPES)
        .map(|entries| entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    let exists = |name: &str| pipes.iter().any(|p| p.eq_ignore_ascii_case(name));
    let mut found = Vec::new();
    let from_env = std::env::var("DOCKER_HOST").ok().and_then(|h| npipe_name(&h));
    if let Some(name) = from_env.into_iter().chain(["docker_engine".to_string()]).find(|name| exists(name)) {
        found.push(Endpoint::local(Engine::Docker, format!("{PIPES}{name}")));
    }
    // La máquina por defecto de Podman primero; si no hay, la primera por nombre.
    let mut machines: Vec<&String> = pipes.iter().filter(|p| p.starts_with("podman-machine-")).collect();
    machines.sort_by_key(|p| (p.as_str() != "podman-machine-default", p.as_str()));
    if let Some(name) = machines.first() {
        found.push(Endpoint::local(Engine::Podman, format!("{PIPES}{name}")));
    }
    found
}

/// Nombre de la tubería de un `DOCKER_HOST` como `npipe:////./pipe/docker_engine`.
#[cfg_attr(not(windows), allow(dead_code))]
fn npipe_name(host: &str) -> Option<String> {
    let path = host.strip_prefix("npipe://")?.replace('\\', "/");
    let name = path.trim_start_matches('/').strip_prefix("./pipe/")?;
    (!name.is_empty()).then(|| name.to_string())
}

/// Motores con socket en este equipo: Docker (`DOCKER_HOST`, el socket de sistema o el rootless) y Podman.
#[cfg(not(windows))]
pub fn detect_endpoints() -> Vec<Endpoint> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let home = std::env::home_dir();
    let mut docker: Vec<PathBuf> = Vec::new();
    if let Some(host) = std::env::var("DOCKER_HOST").ok().and_then(|h| h.strip_prefix("unix://").map(PathBuf::from)) {
        docker.push(host);
    }
    docker.push("/var/run/docker.sock".into());
    if let Some(runtime) = &runtime {
        docker.push(runtime.join("docker.sock"));
    }
    if let Some(home) = &home {
        docker.push(home.join(".docker/run/docker.sock"));
    }
    let mut podman: Vec<PathBuf> = Vec::new();
    if let Some(runtime) = &runtime {
        podman.push(runtime.join("podman/podman.sock"));
    }
    podman.push("/run/podman/podman.sock".into());

    let mut found = Vec::new();
    for (engine, candidates) in [(Engine::Docker, docker), (Engine::Podman, podman)] {
        if let Some(socket) = candidates.into_iter().find(|p| p.exists()) {
            found.push(Endpoint::local(engine, socket));
        }
    }
    found
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Stream = Box<dyn Io>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    /// `running`, `exited`, `created`, `paused`…
    pub state: String,
    /// Texto del motor: «Up 19 minutes», «Exited (0) 2 days ago».
    pub status: String,
    pub ports: String,
}

impl Container {
    pub fn is_running(&self) -> bool {
        matches!(self.state.as_str(), "running" | "restarting")
    }

    /// Salió con un código distinto de cero.
    pub fn failed(&self) -> bool {
        self.state == "exited" && !self.status.contains("Exited (0)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
}

impl Action {
    fn path(self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
            Action::Restart => "restart",
        }
    }
}

/// Interpreta la respuesta de `/containers/json`.
pub fn parse_containers(body: &[u8]) -> anyhow::Result<Vec<Container>> {
    let value: Value = serde_json::from_slice(body).context("respuesta inválida del motor")?;
    let list = value.as_array().context("el motor no devolvió una lista")?;
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    Ok(list
        .iter()
        .map(|item| {
            let name = item
                .get("Names")
                .and_then(Value::as_array)
                .and_then(|names| names.first())
                .and_then(Value::as_str)
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_default();
            let mut ports: Vec<String> = Vec::new();
            for port in item.get("Ports").and_then(Value::as_array).into_iter().flatten() {
                let Some(public) = port.get("PublicPort").and_then(Value::as_u64) else { continue };
                let private = port.get("PrivatePort").and_then(Value::as_u64).unwrap_or(0);
                let kind = port.get("Type").and_then(Value::as_str).unwrap_or("tcp");
                let label = if public == private { format!("{public}/{kind}") } else { format!("{public}→{private}/{kind}") };
                if !ports.contains(&label) {
                    ports.push(label);
                }
            }
            Container { id: text(item, "Id"), name, image: text(item, "Image"), state: text(item, "State"), status: text(item, "Status"), ports: ports.join(", ") }
        })
        .collect())
}

/// Decodifica un cuerpo con `Transfer-Encoding: chunked`.
fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(end) = data.windows(2).position(|w| w == b"\r\n") else { break };
        let size = usize::from_str_radix(String::from_utf8_lossy(&data[..end]).split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        data = &data[end + 2..];
        if size == 0 || data.len() < size {
            break;
        }
        out.extend_from_slice(&data[..size]);
        data = data.get(size + 2..).unwrap_or(&[]);
    }
    out
}

#[cfg(unix)]
async fn connect_socket(path: &std::path::Path) -> io::Result<Stream> {
    Ok(Box::new(tokio::net::UnixStream::connect(path).await?))
}

#[cfg(windows)]
async fn connect_socket(path: &std::path::Path) -> io::Result<Stream> {
    use tokio::net::windows::named_pipe::ClientOptions;
    const ERROR_PIPE_BUSY: i32 = 231;
    // Con todas las instancias de la tubería ocupadas se reintenta; el tiempo límite lo pone quien llama.
    loop {
        match ClientOptions::new().open(path) {
            Ok(pipe) => return Ok(Box::new(pipe)),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(any(unix, windows)))]
async fn connect_socket(_path: &std::path::Path) -> io::Result<Stream> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "plataforma sin sockets Unix ni tuberías con nombre"))
}

/// Mensaje con la causa y qué hacer cuando no se puede abrir el socket.
fn connect_error(endpoint: &Endpoint, error: &io::Error) -> anyhow::Error {
    let path = endpoint.socket.display();
    match error.kind() {
        io::ErrorKind::PermissionDenied if cfg!(windows) => anyhow!(
            "Permiso denegado en {path}. Con Docker Desktop hay que estar en el grupo local «docker-users» y volver a iniciar sesión."
        ),
        io::ErrorKind::PermissionDenied => anyhow!(
            "Permiso denegado en {path}. En Linux hay que estar en el grupo «docker»:\n  sudo usermod -aG docker $USER\nY volver a iniciar sesión."
        ),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => anyhow!("{} no está en marcha ({path}).", endpoint.engine.name()),
        _ => anyhow!("No se pudo hablar con {} en {path}: {error}", endpoint.engine.name()),
    }
}

fn request_bytes(method: &str, path: &str, body: Option<&Value>, upgrade: bool) -> Vec<u8> {
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: engine\r\n");
    if upgrade {
        head.push_str("Connection: Upgrade\r\nUpgrade: tcp\r\n");
    } else {
        head.push_str("Connection: close\r\n");
    }
    if !body.is_empty() || method == "POST" {
        head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    head.push_str(&body);
    head.into_bytes()
}

#[derive(Clone)]
pub struct Client {
    endpoint: Endpoint,
}

impl Client {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    async fn dial(&self) -> anyhow::Result<Stream> {
        if let Via::Ssh(link) = &self.endpoint.via {
            return self.dial_ssh(link).await;
        }
        match tokio::time::timeout(TIMEOUT, connect_socket(&self.endpoint.socket)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(error)) => Err(connect_error(&self.endpoint, &error)),
            Err(_) => bail!("Tiempo de espera agotado al conectar con {}", self.endpoint.engine.name()),
        }
    }

    /// Un canal `direct-streamlocal` hasta el socket del servidor, dentro de la sesión SSH compartida.
    async fn dial_ssh(&self, link: &SshLink) -> anyhow::Result<Stream> {
        let session = link.session().await?;
        let socket = self.endpoint.socket.to_string_lossy().into_owned();
        let opened = tokio::time::timeout(TIMEOUT, session.channel_open_direct_streamlocal(socket.clone())).await;
        match opened {
            Ok(Ok(channel)) => Ok(Box::new(channel.into_stream())),
            Ok(Err(russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::AdministrativelyProhibited))) => bail!(
                "{} no permite reenviar sockets por SSH. Activa «AllowStreamLocalForwarding yes» en su sshd_config.",
                link.name()
            ),
            Ok(Err(error)) => bail!("No se pudo llegar a {socket} en {}: {error}. ¿Está {} en marcha?", link.name(), self.endpoint.engine.name()),
            Err(_) => bail!("Tiempo de espera agotado al conectar con {} en {}", self.endpoint.engine.name(), link.name()),
        }
    }

    /// Petición normal: devuelve el código HTTP y el cuerpo.
    async fn call(&self, method: &str, path: &str, body: Option<&Value>, limit: Duration) -> anyhow::Result<(u16, Vec<u8>)> {
        let mut stream = self.dial().await?;
        stream.write_all(&request_bytes(method, path, body, false)).await?;
        let mut raw = Vec::new();
        tokio::time::timeout(limit, stream.read_to_end(&mut raw)).await.map_err(|_| anyhow!("El motor no respondió a tiempo"))??;
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").context("respuesta HTTP incompleta del motor")?;
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let status: u16 = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).context("línea de estado inválida")?;
        let body = &raw[split + 4..];
        let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") { dechunk(body) } else { body.to_vec() };
        Ok((status, body))
    }

    fn failure(status: u16, body: &[u8]) -> anyhow::Error {
        let message = serde_json::from_slice::<Value>(body).ok().and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string));
        anyhow!("{}", message.unwrap_or_else(|| format!("el motor respondió {status}")))
    }

    pub async fn list(&self) -> anyhow::Result<Vec<Container>> {
        let (status, body) = self.call("GET", "/containers/json?all=1", None, TIMEOUT).await?;
        if status != 200 {
            return Err(Self::failure(status, &body));
        }
        parse_containers(&body)
    }

    pub async fn act(&self, id: &str, action: Action) -> anyhow::Result<()> {
        let (status, body) = self.call("POST", &format!("/containers/{id}/{}", action.path()), None, ACTION_TIMEOUT).await?;
        // 304: ya estaba en ese estado.
        match status {
            200 | 204 | 304 => Ok(()),
            _ => Err(Self::failure(status, &body)),
        }
    }

    /// Crea un `exec` con tty y lo arranca; devuelve su id y el flujo en bruto.
    async fn exec(&self, id: &str, size: (usize, usize)) -> anyhow::Result<(String, Stream)> {
        let command = json!({
            "AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Tty": true,
            "Env": ["TERM=xterm-256color", "COLORTERM=truecolor", format!("COLUMNS={}", size.0), format!("LINES={}", size.1)],
            "Cmd": ["/bin/sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash || exec sh"],
        });
        let (status, body) = self.call("POST", &format!("/containers/{id}/exec"), Some(&command), TIMEOUT).await?;
        if status != 201 {
            return Err(Self::failure(status, &body));
        }
        let exec_id = serde_json::from_slice::<Value>(&body)?.get("Id").and_then(Value::as_str).context("el motor no devolvió el id del exec")?.to_string();

        let mut stream = self.dial().await?;
        stream.write_all(&request_bytes("POST", &format!("/exec/{exec_id}/start"), Some(&json!({"Detach": false, "Tty": true})), true)).await?;
        // La cabecera se lee byte a byte para no consumir nada del flujo que viene detrás.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await? == 0 {
                bail!("el motor cerró la conexión al abrir el shell");
            }
            head.push(byte[0]);
            if head.len() > 8192 {
                bail!("cabecera demasiado larga");
            }
        }
        let first = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string();
        if !first.contains(" 101 ") && !first.contains(" 200 ") {
            bail!("no se pudo abrir el shell: {first}");
        }
        Ok((exec_id, stream))
    }

    /// `true` si el motor está tras una sesión SSH que se ha cerrado.
    async fn link_dropped(&self) -> bool {
        let Via::Ssh(link) = &self.endpoint.via else { return false };
        // El cierre del transporte llega un instante después que el del canal.
        tokio::time::sleep(Duration::from_millis(300)).await;
        link.is_lost()
    }

    async fn resize(&self, exec_id: &str, cols: usize, rows: usize) {
        let _ = self.call("POST", &format!("/exec/{exec_id}/resize?h={rows}&w={cols}"), None, TIMEOUT).await;
    }
}

enum Message {
    Input(Vec<u8>),
    Resize(usize, usize),
}

struct DockerBackend {
    tx: UnboundedSender<Message>,
}

impl Backend for DockerBackend {
    fn write(&self, bytes: &[u8]) {
        let _ = self.tx.send(Message::Input(bytes.to_vec()));
    }

    fn resize(&self, cols: usize, rows: usize) {
        let _ = self.tx.send(Message::Resize(cols, rows));
    }
}

fn red(text: &str) -> String {
    format!("\r\n\x1b[31m{text}\x1b[0m\r\n")
}

/// Abre un shell dentro del contenedor; el progreso y los errores salen en la propia terminal.
pub fn spawn(handle: &tokio::runtime::Handle, endpoint: Endpoint, id: String, name: String, size: (usize, usize), feed: Feed) -> Arc<dyn Backend> {
    let (tx, rx) = unbounded_channel::<Message>();
    handle.spawn(run_shell(Client::new(endpoint), id, name, size, feed, rx));
    Arc::new(DockerBackend { tx })
}

async fn run_shell(client: Client, id: String, name: String, size: (usize, usize), mut feed: Feed, mut rx: tokio::sync::mpsc::UnboundedReceiver<Message>) {
    feed.feed(format!("Abriendo un shell en {name}\u{2026}\r\n").as_bytes());
    let (exec_id, stream) = match client.exec(&id, size).await {
        Ok(opened) => opened,
        Err(error) => {
            feed.feed(red(&format!("{error:#}")).as_bytes());
            feed.disconnect();
            return;
        }
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = [0u8; 8192];
    loop {
        tokio::select! {
            read = reader.read(&mut buffer) => match read {
                // Fin del flujo: el shell terminó, salvo que lo que se cayó fuera la sesión SSH.
                Ok(0) => {
                    if client.link_dropped().await {
                        feed.feed(red("Se perdió la conexión SSH").as_bytes());
                        feed.disconnect();
                    } else {
                        feed.close();
                    }
                    return;
                }
                Ok(n) => feed.feed(&buffer[..n]),
                Err(error) => {
                    feed.feed(red(&format!("Conexión perdida: {error}")).as_bytes());
                    feed.disconnect();
                    return;
                }
            },
            message = rx.recv() => match message {
                Some(Message::Input(bytes)) => {
                    if writer.write_all(&bytes).await.is_err() {
                        feed.disconnect();
                        return;
                    }
                }
                Some(Message::Resize(cols, rows)) => client.resize(&exec_id, cols, rows).await,
                None => return,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const LIST: &str = r#"[
        {"Id":"aaa111","Names":["/minio"],"Image":"minio/minio:latest","State":"running","Status":"Up 19 minutes",
         "Ports":[{"IP":"0.0.0.0","PrivatePort":9000,"PublicPort":9000,"Type":"tcp"},{"IP":"::","PrivatePort":9000,"PublicPort":9000,"Type":"tcp"},{"PrivatePort":9001,"PublicPort":19001,"Type":"tcp"},{"PrivatePort":5432,"Type":"tcp"}]},
        {"Id":"bbb222","Names":["/mc-35"],"Image":"itzg/minecraft-server","State":"exited","Status":"Exited (0) 2 days ago","Ports":[]},
        {"Id":"ccc333","Names":["/keycloak"],"Image":"keycloak","State":"exited","Status":"Exited (143) 2 months ago","Ports":[]}
    ]"#;

    #[test]
    fn containers_are_parsed_with_state_and_published_ports() {
        let list = parse_containers(LIST.as_bytes()).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!((list[0].name.as_str(), list[0].is_running()), ("minio", true));
        assert_eq!(list[0].ports, "9000/tcp, 19001→9001/tcp");
        assert!(!list[1].is_running() && !list[1].failed());
        assert!(list[2].failed());
        assert!(parse_containers(b"{}").is_err());
    }

    #[test]
    fn chunked_bodies_are_decoded() {
        assert_eq!(dechunk(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), b"hello world");
    }

    #[test]
    fn the_remote_probe_separates_usable_and_denied_sockets() {
        let output = "ok /var/run/docker.sock\ndenied /run/podman/podman.sock\nok /var/run/docker.sock\nbasura\n";
        let (usable, denied) = parse_probe(output);
        assert_eq!(usable, ["/var/run/docker.sock"]);
        assert_eq!(denied, ["/run/podman/podman.sock"]);
        assert_eq!(Endpoint::fixed("/run/user/1000/podman/podman.sock", Via::Local).engine, Engine::Podman);
        assert_eq!(Endpoint::fixed("/var/run/docker.sock", Via::Local).engine, Engine::Docker);
    }

    #[test]
    fn docker_host_names_a_pipe() {
        assert_eq!(npipe_name("npipe:////./pipe/docker_engine").as_deref(), Some("docker_engine"));
        assert_eq!(npipe_name(r"npipe://\\.\pipe\dockerDesktopLinuxEngine").as_deref(), Some("dockerDesktopLinuxEngine"));
        assert_eq!(npipe_name("unix:///var/run/docker.sock"), None);
        assert_eq!(npipe_name("npipe:////./pipe/"), None);
    }

    #[cfg(unix)]
    async fn serve(listener: tokio::net::UnixListener, log: Arc<Mutex<Vec<String>>>) {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            tokio::spawn(answer(stream, log.clone()));
        }
    }

    /// En una tubería con nombre cada conexión ocupa una instancia: se crea la siguiente antes de atenderla.
    #[cfg(windows)]
    async fn serve(name: String, mut server: tokio::net::windows::named_pipe::NamedPipeServer, log: Arc<Mutex<Vec<String>>>) {
        use tokio::net::windows::named_pipe::ServerOptions;
        while server.connect().await.is_ok() {
            let next = ServerOptions::new().create(&name).unwrap();
            tokio::spawn(answer(std::mem::replace(&mut server, next), log.clone()));
        }
    }

    /// Motor mínimo: lista, acciones y un `exec` que repite lo que se escribe.
    async fn answer(mut stream: impl Io + 'static, log: Arc<Mutex<Vec<String>>>) {
        let mut raw = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let Ok(n) = stream.read(&mut buffer).await else { return };
            if n == 0 {
                return;
            }
            raw.extend_from_slice(&buffer[..n]);
            if let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..split]).into_owned();
                let length = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                if raw.len() >= split + 4 + length {
                    break;
                }
            }
        }
        let line = String::from_utf8_lossy(&raw).lines().next().unwrap_or("").to_string();
        log.lock().unwrap().push(line.clone());
        let reply = |status: &str, body: &str| format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        if line.starts_with("GET /containers/json") {
            let _ = stream.write_all(reply("200 OK", LIST).as_bytes()).await;
        } else if line.contains("/containers/bbb222/start") {
            let _ = stream.write_all(reply("204 No Content", "").as_bytes()).await;
        } else if line.contains("/containers/aaa111/stop") {
            let _ = stream.write_all(reply("304 Not Modified", "").as_bytes()).await;
        } else if line.contains("/containers/zzz/restart") {
            let _ = stream.write_all(reply("404 Not Found", r#"{"message":"No such container: zzz"}"#).as_bytes()).await;
        } else if line.contains("/containers/aaa111/exec") {
            let _ = stream.write_all(reply("201 Created", r#"{"Id":"exec1"}"#).as_bytes()).await;
        } else if line.contains("/exec/exec1/start") {
            let _ = stream.write_all(b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n# ").await;
            let mut buffer = [0u8; 256];
            loop {
                let Ok(n) = stream.read(&mut buffer).await else { return };
                if n == 0 {
                    return;
                }
                let _ = stream.write_all(&buffer[..n]).await;
            }
        } else {
            let _ = stream.write_all(reply("404 Not Found", "{}").as_bytes()).await;
        }
    }

    #[cfg(unix)]
    fn start() -> (Client, Arc<Mutex<Vec<String>>>, PathBuf) {
        let socket = std::env::temp_dir().join(format!("omniterm-docker-{}-{:?}.sock", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(serve(listener, log.clone()));
        (Client::new(Endpoint::local(Engine::Docker, socket.clone())), log, socket)
    }

    #[cfg(windows)]
    fn start() -> (Client, Arc<Mutex<Vec<String>>>, PathBuf) {
        use tokio::net::windows::named_pipe::ServerOptions;
        let name = format!(r"{PIPES}omniterm-docker-{}-{:?}", std::process::id(), std::thread::current().id());
        // La primera instancia se crea aquí para que exista antes de que el cliente conecte.
        let first = ServerOptions::new().first_pipe_instance(true).create(&name).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(serve(name.clone(), first, log.clone()));
        (Client::new(Endpoint::local(Engine::Docker, name.clone())), log, name.into())
    }

    #[tokio::test]
    async fn lists_and_acts_on_containers() {
        let (client, log, socket) = start();
        let list = client.list().await.unwrap();
        assert_eq!(list.len(), 3);
        client.act("bbb222", Action::Start).await.unwrap();
        client.act("aaa111", Action::Stop).await.unwrap();
        let error = client.act("zzz", Action::Restart).await.unwrap_err().to_string();
        assert_eq!(error, "No such container: zzz");
        let log = log.lock().unwrap().clone();
        assert!(log.iter().any(|l| l.starts_with("GET /containers/json?all=1")));
        assert!(log.iter().any(|l| l.starts_with("POST /containers/bbb222/start")));
        std::fs::remove_file(socket).ok();
    }

    #[tokio::test]
    async fn the_shell_is_a_raw_stream_after_the_upgrade() {
        let (client, _, socket) = start();
        let (exec_id, mut stream) = client.exec("aaa111", (80, 24)).await.unwrap();
        assert_eq!(exec_id, "exec1");
        let mut prompt = [0u8; 2];
        stream.read_exact(&mut prompt).await.unwrap();
        assert_eq!(&prompt, b"# ");
        stream.write_all(b"ls\r").await.unwrap();
        let mut echo = [0u8; 3];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ls\r");
        std::fs::remove_file(socket).ok();
    }

    #[tokio::test]
    async fn a_missing_socket_explains_itself() {
        let client = Client::new(Endpoint::local(Engine::Podman, "/no/existe.sock"));
        let error = client.list().await.unwrap_err().to_string();
        assert!(error.contains("Podman no está en marcha"), "{error}");
    }

    /// El motor de «un servidor»: un socket Unix al que se llega por un sshd real con `direct-streamlocal`.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_remote_engine_is_reached_through_an_ssh_tunnel() {
        use crate::connect::ssh::{Credentials, JumpHost, UiEvent};
        use crate::data::store::{Auth, Connection, Protocol};

        let Some(sshd) = crate::testutil::PrivateSshd::start() else { return };
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let (events, requests) = std::sync::mpsc::channel();
        // Se confía en la huella del servidor de pruebas en cuanto se pregunta.
        std::thread::spawn(move || {
            for event in requests {
                if let UiEvent::HostKey(request) = event {
                    let _ = request.reply.send(true);
                }
            }
        });
        let server = Connection {
            id: Some(1),
            protocol: Protocol::Ssh,
            name: "servidor".into(),
            host: "127.0.0.1".into(),
            port: sshd.port,
            user: sshd.user.clone(),
            auth: Auth::Key,
            key_path: Some(sshd.key_path.clone()),
            init_command: None,
            jump: None,
            color: None,
            env: None,
            vars: String::new(),
        };
        let link = Arc::new(SshLink::new(JumpHost { connection: server, credentials: Credentials::default() }, events, Arc::new(|| {}), sshd.dir.join("known_hosts")));
        let socket = sshd.dir.join("docker.sock");

        runtime.block_on(async {
            let log = Arc::new(Mutex::new(Vec::new()));
            tokio::spawn(serve(tokio::net::UnixListener::bind(&socket).unwrap(), log.clone()));
            let client = Client::new(Endpoint::fixed(socket.to_str().unwrap(), Via::Ssh(link.clone())));

            assert_eq!(client.list().await.unwrap().len(), 3);
            client.act("bbb222", Action::Start).await.unwrap();
            let (_, mut stream) = client.exec("aaa111", (80, 24)).await.unwrap();
            let mut prompt = [0u8; 2];
            stream.read_exact(&mut prompt).await.unwrap();
            assert_eq!(&prompt, b"# ");
            assert!(!link.is_lost());
            assert!(log.lock().unwrap().iter().any(|l| l.starts_with("POST /containers/bbb222/start")));

            // Un socket que no existe en el servidor da un error que nombra la conexión.
            let missing = Client::new(Endpoint::fixed("/no/existe.sock", Via::Ssh(link.clone())));
            let error = missing.list().await.unwrap_err().to_string();
            assert!(error.contains("servidor"), "{error}");
        });
    }
}
