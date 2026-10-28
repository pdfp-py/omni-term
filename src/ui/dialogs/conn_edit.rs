//! Pantalla de edición de conexión: lista de tipos y las filas de cada tipo.

use super::*;

pub(super) fn environment_row(ui: &mut egui::Ui, form: &mut ConnForm) {
    crate::ui::kit::form_row(ui, "Entorno", |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(3.0, 6.0);
            let none = form.env.trim().is_empty() && form.color.is_none();
            for (name, env, color) in ENVIRONMENTS {
                let selected = !form.custom_env && form.env.eq_ignore_ascii_case(env) && form.color == Some(color);
                if crate::ui::kit::chip(ui, name, Some(theme::identity(color)), selected).on_hover_text(if selected { "Clic para quitarlo" } else { "Pone la etiqueta y el color" }).clicked() {
                    // Pulsar el elegido lo quita: sin entorno ni color.
                    if selected {
                        form.env.clear();
                        form.color = None;
                    } else {
                        form.env = env.to_string();
                        form.color = Some(color);
                    }
                    form.custom_env = false;
                }
            }
            let custom_selected = form.custom_env || (!none && !ENVIRONMENTS.iter().any(|(_, e, c)| form.env.eq_ignore_ascii_case(e) && form.color == Some(*c)));
            if crate::ui::kit::chip(ui, "Otro…", None, custom_selected).on_hover_text("Elegir la etiqueta y el color a mano").clicked() {
                form.custom_env = true;
            }
        });
    });
    if form.custom_env {
        ui.add_space(theme::space::ROW);
        crate::ui::kit::form_row(ui, "Etiqueta", |ui| {
            let width = ui.available_width();
            ui.add_sized([width, theme::height::FIELD], TextEdit::singleline(&mut form.env).hint_text("por ejemplo, pre-producción").align(egui::Align2::LEFT_CENTER));
        });
        ui.add_space(theme::space::ROW);
        crate::ui::kit::form_row(ui, "Color", |ui| {
            ui.horizontal(|ui| {
                for choice in std::iter::once(None).chain((0..6).map(Some)) {
                    let (rect, response) = ui.allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::click());
                    let response = response.hand();
                    match choice.map(theme::identity) {
                        Some(color) => ui.painter().circle_filled(rect.center(), 8.0, color),
                        None => ui.painter().circle_stroke(rect.center(), 8.0, egui::Stroke::new(theme::stroke::MEDIUM, theme::subtext())),
                    };
                    if form.color == choice {
                        ui.painter().circle_stroke(rect.center(), 11.0, egui::Stroke::new(theme::stroke::THICK, theme::text()));
                    }
                    let name = choice.map_or("Sin color", |i| theme::IDENTITY_NAMES[i as usize]);
                    if response.on_hover_text(name).clicked() {
                        form.color = choice;
                    }
                }
            });
        });
    }
}

/// El puerto por defecto sigue al protocolo mientras no se haya tocado.
pub(super) fn set_default_port(form: &mut ConnForm) {
    let target = match (form.telnet, form.files) {
        (true, _) => "23",
        (_, 2) if form.ftp_tls == FtpTls::Implicit => "990",
        (_, 2) => "21",
        (_, 3) => "445",
        _ => "22",
    };
    if matches!(form.port.trim(), "21" | "22" | "23" | "445" | "990") {
        form.port = target.into();
    }
}

/// Filas propias de FTP (cuenta y seguridad) y de SMB (recurso compartido, cuenta y dominio).
pub(super) fn files_rows(ui: &mut egui::Ui, form: &mut ConnForm) {
    if form.files == 3 {
        ui.add_space(theme::space::ROW);
        crate::ui::kit::form_row(ui, "Recurso", |ui| {
            let width = ui.available_width();
            crate::ui::kit::text_input(ui, &mut form.smb_share, width, "nombre del recurso compartido", &mut form.errors.share);
            crate::ui::kit::error_line(ui, &form.errors.share);
        });
    }
    if form.files == 2 {
        ui.add_space(theme::space::ROW);
        crate::ui::kit::form_row(ui, "Cuenta", |ui| {
            crate::ui::kit::switch_labeled(ui, &mut form.ftp_anonymous, "Acceso anónimo");
        });
    }
    if form.files == 3 || !form.ftp_anonymous {
        ui.add_space(theme::space::ROW);
        crate::ui::kit::form_row(ui, "Usuario", |ui| {
            let width = ui.available_width();
            crate::ui::kit::text_input(ui, &mut form.user, width, "usuario", &mut form.errors.user);
            crate::ui::kit::error_line(ui, &form.errors.user);
        });
    }
    if form.files == 3 {
        ui.add_space(theme::space::ROW);
        crate::ui::kit::form_row(ui, "Dominio", |ui| {
            let width = ui.available_width();
            ui.add_sized([width, theme::height::FIELD], TextEdit::singleline(&mut form.smb_domain).hint_text("opcional").align(egui::Align2::LEFT_CENTER));
        });
    } else {
        ui.add_space(theme::space::ROW);
        crate::ui::kit::form_row(ui, "Seguridad", |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                for (tls, label) in [(FtpTls::None, "Sin cifrar"), (FtpTls::Explicit, "FTPS explícito"), (FtpTls::Implicit, "FTPS implícito")] {
                    if ui.selectable_label(form.ftp_tls == tls, label).hand().clicked() && form.ftp_tls != tls {
                        form.ftp_tls = tls;
                        set_default_port(form);
                    }
                }
            });
        });
        ui.add_space(theme::space::ROW);
        crate::ui::kit::form_row(ui, "Modo", |ui| {
            crate::ui::kit::switch_labeled(ui, &mut form.ftp_passive, "Pasivo (recomendado tras un cortafuegos)");
        });
        if form.ftp_tls == FtpTls::None {
            ui.add_space(theme::space::ROW);
            crate::ui::kit::form_row(ui, "", |ui| {
                ui.label(RichText::new("FTP sin cifrar: la contraseña y los archivos viajan en texto claro.").small().color(theme::red()));
            });
        }
    }
}

/// Filas del formulario de una conexión serie: puerto, velocidad, formato, flujo, Enter y eco.
pub(super) fn adb_rows(ui: &mut egui::Ui, form: &mut ConnForm) {
    crate::ui::kit::form_row(ui, "Dispositivo", |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let width = (ui.available_width() - 90.0 - 8.0).max(120.0);
            crate::ui::kit::text_input(ui, &mut form.host, width, "vacío: el único conectado", &mut form.errors.host);
            let detect = crate::ui::kit::button_with(ui, egui::Button::new("Detectar").min_size(egui::vec2(90.0, theme::height::FIELD)), crate::ui::kit::Variant::Secondary);
            if detect.clicked() {
                let slot: AdbDevices = std::sync::Arc::new(std::sync::Mutex::new(None));
                let result = slot.clone();
                let ctx = ui.ctx().clone();
                std::thread::spawn(move || {
                    *result.lock().unwrap() = Some(crate::files::adb::detect());
                    ctx.request_repaint();
                });
                form.adb_devices = Some(slot);
            }
            egui::Popup::menu(&detect).show(|ui| {
                ui.set_min_width(300.0);
                let found = form.adb_devices.as_ref().map(|slot| slot.lock().unwrap().clone());
                match found {
                    None | Some(None) => {
                        ui.label(RichText::new("Buscando dispositivos…").color(theme::subtext()));
                    }
                    Some(Some(Err(error))) => {
                        ui.label(RichText::new(error).color(theme::red()));
                    }
                    Some(Some(Ok(devices))) if devices.is_empty() => {
                        ui.label(RichText::new("No hay dispositivos. Activa la depuración USB y enchufa el móvil.").color(theme::subtext()));
                    }
                    Some(Some(Ok(devices))) => {
                        for device in devices {
                            let label = if device.description.is_empty() { device.serial.clone() } else { format!("{}   {}", device.serial, device.description) };
                            let label = if device.state == "device" { label } else { format!("{label}   ({})", device.state) };
                            if ui.button(label).clicked() {
                                form.host = device.serial;
                                ui.close();
                            }
                        }
                    }
                }
            });
        });
        crate::ui::kit::error_line(ui, &form.errors.host);
        ui.label(RichText::new("Para un móvil por Wi-Fi escribe ip:puerto (por ejemplo 192.168.1.5:5555).").small().color(theme::subtext()));
    });
}

pub(super) fn serial_rows(ui: &mut egui::Ui, form: &mut ConnForm) {
    crate::ui::kit::form_row(ui, "Puerto", |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let width = (ui.available_width() - 90.0 - 8.0).max(120.0);
            crate::ui::kit::text_input(ui, &mut form.host, width, if cfg!(windows) { "COM3" } else { "/dev/ttyUSB0" }, &mut form.errors.host);
            let detect = crate::ui::kit::button_with(ui, egui::Button::new("Detectar").min_size(egui::vec2(90.0, theme::height::FIELD)), crate::ui::kit::Variant::Secondary);
            if detect.clicked() {
                form.ports = crate::connect::serial::detect_ports();
            }
            egui::Popup::menu(&detect).show(|ui| {
                ui.set_min_width(260.0);
                if form.ports.is_empty() {
                    ui.label(RichText::new("No se detectó ningún puerto.").color(theme::subtext()));
                }
                for (path, description) in form.ports.clone() {
                    let label = if description.is_empty() { path.clone() } else { format!("{path}   {description}") };
                    if ui.button(label).clicked() {
                        form.host = path;
                        ui.close();
                    }
                }
            });
        });
        crate::ui::kit::error_line(ui, &form.errors.host);
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Velocidad", |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            crate::ui::kit::text_input(ui, &mut form.baud, 100.0, "115200", &mut form.errors.port);
            let speeds = crate::ui::kit::button_with(ui, egui::Button::new(format!("{}  baudios", crate::ui::icons::CARET_DOWN)).min_size(egui::vec2(0.0, theme::height::FIELD)), crate::ui::kit::Variant::Secondary);
            egui::Popup::menu(&speeds).show(|ui| {
                for rate in BAUD_RATES {
                    if ui.button(rate.to_string()).clicked() {
                        form.baud = rate.to_string();
                        ui.close();
                    }
                }
            });
        });
        crate::ui::kit::error_line(ui, &form.errors.port);
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Formato", |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            for bits in [5u8, 6, 7, 8] {
                ui.selectable_value(&mut form.data_bits, bits, bits.to_string());
            }
            ui.add_space(theme::space::M);
            for (parity, label) in [(Parity::None, "Sin paridad"), (Parity::Odd, "Impar"), (Parity::Even, "Par")] {
                ui.selectable_value(&mut form.parity, parity, label);
            }
            ui.add_space(theme::space::M);
            for stop in [1u8, 2] {
                ui.selectable_value(&mut form.stop_bits, stop, format!("{stop} parada"));
            }
        });
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Flujo", |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            for (flow, label) in [(Flow::None, "Ninguno"), (Flow::Software, "XON/XOFF"), (Flow::Hardware, "RTS/CTS")] {
                ui.selectable_value(&mut form.flow, flow, label);
            }
        });
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Enter envía", |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            for (newline, label) in Newline::ALL {
                ui.selectable_value(&mut form.newline, newline, label);
            }
            ui.add_space(theme::space::L);
            crate::ui::kit::switch_labeled(ui, &mut form.local_echo, "Eco local");
        });
    });
}

/// Tipos de conexión del selector: añadir uno nuevo es una fila aquí y sus brazos en `ConnKind::of` y `apply`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ConnKind {
    Ssh,
    Telnet,
    Serial,
    Sftp,
    Ftp,
    Smb,
    Adb,
    Local,
    Engine,
}

impl ConnKind {
    /// (tipo, nombre, grupo): la lista pone un encabezado cada vez que cambia el grupo.
    const ALL: [(ConnKind, &'static str, &'static str); 9] = [
        (ConnKind::Ssh, "SSH", "Terminal"),
        (ConnKind::Telnet, "Telnet", "Terminal"),
        (ConnKind::Serial, "Puerto serie", "Terminal"),
        (ConnKind::Local, "Local", "Terminal"),
        (ConnKind::Sftp, "SFTP", "Archivos"),
        (ConnKind::Ftp, "FTP / FTPS", "Archivos"),
        (ConnKind::Smb, "SMB", "Archivos"),
        (ConnKind::Adb, "Android (ADB)", "Otros"),
        (ConnKind::Engine, "Contenedores", "Otros"),
    ];

    pub(super) fn of(form: &ConnForm) -> Self {
        if form.engine {
            return ConnKind::Engine;
        }
        match (form.files, form.adb, form.serial, form.telnet, form.local) {
            (1, ..) => ConnKind::Sftp,
            (2, ..) => ConnKind::Ftp,
            (3, ..) => ConnKind::Smb,
            (_, true, ..) => ConnKind::Adb,
            (_, _, true, ..) => ConnKind::Serial,
            (_, _, _, true, _) => ConnKind::Telnet,
            (.., true) => ConnKind::Local,
            _ => ConnKind::Ssh,
        }
    }

    pub(super) fn apply(self, form: &mut ConnForm) {
        form.telnet = self == ConnKind::Telnet;
        form.adb = self == ConnKind::Adb;
        form.serial = self == ConnKind::Serial;
        form.local = self == ConnKind::Local;
        form.engine = self == ConnKind::Engine;
        form.files = match self {
            ConnKind::Sftp => 1,
            ConnKind::Ftp => 2,
            ConnKind::Smb => 3,
            _ => 0,
        };
        set_default_port(form);
    }
}

impl ConnKind {
    pub(super) fn icon(self) -> &'static str {
        use crate::ui::icons;
        match self {
            ConnKind::Ssh => icons::TERMINAL,
            ConnKind::Telnet => icons::PROMPT,
            ConnKind::Serial => icons::USB,
            ConnKind::Sftp => icons::FOLDER_LOCK,
            ConnKind::Ftp => icons::CLOUD_UP,
            ConnKind::Smb => icons::HARD_DRIVES,
            ConnKind::Adb => icons::PHONE,
            ConnKind::Local => icons::DESKTOP,
            ConnKind::Engine => icons::CUBE,
        }
    }
}

pub(super) const KIND_LIST_WIDTH: f32 = 176.0;

pub(super) const KIND_ROW_HEIGHT: f32 = 28.0;

/// Lista de tipos de conexión con icono, agrupada con encabezados, en la columna lateral del diálogo.
pub(super) fn kind_list(ui: &mut egui::Ui, form: &mut ConnForm) {
    let current = ConnKind::of(form);
    ui.vertical(|ui| {
        ui.set_width(KIND_LIST_WIDTH);
        egui::Frame::NONE.inner_margin(egui::Margin::same(theme::space::L as i8)).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            let mut group = "";
            for (kind, name, kind_group) in ConnKind::ALL {
                if kind_group != group {
                    if !group.is_empty() {
                        ui.add_space(theme::space::S);
                    }
                    ui.label(RichText::new(kind_group.to_uppercase()).font(FontId::new(theme::size::CAPTION, egui::FontFamily::Proportional)).color(theme::subtext()));
                    group = kind_group;
                }
                let selected = kind == current;
                let (rect, response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), KIND_ROW_HEIGHT), egui::Sense::click());
                let response = response.hand();
                let radius = egui::CornerRadius::same(theme::radius::CONTROL);
                if selected {
                    ui.painter().rect_filled(rect, radius, theme::selection());
                } else if response.hovered() {
                    ui.painter().rect_filled(rect, radius, theme::surface());
                }
                let ink = if selected { theme::text() } else { theme::subtext() };
                ui.painter().text(rect.min + egui::vec2(14.0, KIND_ROW_HEIGHT / 2.0), egui::Align2::CENTER_CENTER, kind.icon(), FontId::proportional(theme::size::ICON), ink);
                let font = FontId::new(theme::size::BODY, if selected { crate::ui::strong_family() } else { egui::FontFamily::Proportional });
                ui.painter().text(rect.min + egui::vec2(32.0, KIND_ROW_HEIGHT / 2.0), egui::Align2::LEFT_CENTER, name, font, ink);
                if response.clicked() && !selected {
                    kind.apply(form);
                }
            }
        });
    });
}

/// Intérpretes instalados, detectados una sola vez por ejecución.
pub(super) fn detected_shells(ctx: &egui::Context) -> std::sync::Arc<Vec<crate::connect::local::ShellOption>> {
    let id = Id::NULL.with("detected-shells");
    ctx.data_mut(|d| d.get_temp_mut_or_insert_with::<std::sync::Arc<Vec<crate::connect::local::ShellOption>>>(id, || std::sync::Arc::new(crate::connect::local::available_shells())).clone())
}

/// Filas de un motor de contenedores: dónde está (este equipo o un servidor por SSH) y su socket.
pub(super) fn engine_rows(ui: &mut egui::Ui, form: &mut ConnForm, connections: &[Connection]) {
    let servers: Vec<&Connection> = connections.iter().filter(|c| c.id != form.id && c.is_ssh()).collect();
    crate::ui::kit::form_row(ui, "Ubicación", |ui| {
        let current = form.jump.and_then(|id| servers.iter().find(|c| c.id == Some(id))).map_or("Este equipo".to_string(), |c| format!("{} ({})", c.name, c.destination()));
        ComboBox::from_id_salt("engine-place")
            .width(ui.available_width())
            .selected_text(current)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut form.jump, None, "Este equipo");
                for server in &servers {
                    ui.selectable_value(&mut form.jump, server.id, format!("{} ({})", server.name, server.destination()));
                }
            })
            .response
            .hand();
        let hint = if servers.is_empty() {
            "Para un servidor, crea antes su conexión SSH: el motor usa su usuario, llave y saltos."
        } else {
            "En un servidor se entra con su conexión SSH y se habla con el motor por un túnel al socket, sin abrir puertos."
        };
        ui.label(RichText::new(hint).small().color(theme::subtext()));
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Socket", |ui| {
        let width = ui.available_width();
        crate::ui::kit::text_input(ui, &mut form.host, width, "detectar al conectar", &mut form.errors.host);
        crate::ui::kit::error_line(ui, &form.errors.host);
        ui.label(RichText::new("Vacío busca Docker y Podman (también rootless). Indícalo solo si está en otro sitio.").small().color(theme::subtext()));
    });
}

/// Filas de un perfil de terminal local: intérprete, argumentos, carpeta inicial, comando inicial y variables.
pub(super) fn local_rows(ui: &mut egui::Ui, form: &mut ConnForm) {
    let shells = detected_shells(ui.ctx());
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Intérprete", |ui| {
        let program = form.host.trim().to_string();
        let args = form.local_args.trim().to_string();
        let matching = shells.iter().find(|o| o.program == program && (o.args.is_empty() || o.args == args));
        let custom = form.local_other || (!program.is_empty() && matching.is_none());
        let selected = if custom {
            "Otro…".to_string()
        } else if let Some(option) = matching {
            option.label.clone()
        } else {
            "Predeterminado del sistema".to_string()
        };
        ComboBox::from_id_salt("local-shell")
            .width(ui.available_width())
            .selected_text(selected)
            .show_ui(ui, |ui| {
                if ui.selectable_label(!custom && program.is_empty(), "Predeterminado del sistema").clicked() {
                    form.host.clear();
                    form.local_other = false;
                }
                for option in shells.iter() {
                    let chosen = !custom && matching.is_some_and(|m| m == option);
                    if ui.selectable_label(chosen, option.label.as_str()).clicked() {
                        form.host = option.program.clone();
                        if !option.args.is_empty() {
                            form.local_args = option.args.clone();
                        }
                        form.local_other = false;
                    }
                }
                if ui.selectable_label(custom, "Otro…").clicked() {
                    form.local_other = true;
                }
            })
            .response
            .hand();
        if custom {
            ui.add_space(theme::space::XS);
            let width = ui.available_width();
            crate::ui::kit::text_input(ui, &mut form.host, width, "ruta del ejecutable", &mut form.errors.host);
        }
        crate::ui::kit::error_line(ui, &form.errors.host);
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Argumentos", |ui| {
        let width = ui.available_width();
        crate::ui::kit::text_input(ui, &mut form.local_args, width, "opcional, por ejemplo -l -i", &mut form.errors.user);
        crate::ui::kit::error_line(ui, &form.errors.user);
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Carpeta inicial", |ui| {
        let width = ui.available_width();
        crate::ui::kit::text_input(ui, &mut form.local_cwd, width, "~ (tu carpeta personal)", &mut form.errors.cwd);
        crate::ui::kit::error_line(ui, &form.errors.cwd);
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Comando inicial", |ui| {
        let width = ui.available_width();
        ui.add_sized(
            [width, theme::height::FIELD],
            TextEdit::singleline(&mut form.init_command).hint_text("opcional, se ejecuta al abrir").align(egui::Align2::LEFT_CENTER),
        );
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Variables", |ui| {
        let width = ui.available_width();
        ui.add_sized(
            [width, 66.0],
            TextEdit::multiline(&mut form.local_vars).hint_text("NOMBRE=valor, una por línea").desired_rows(3),
        );
    });
}

pub(super) fn ssh_access_rows(ui: &mut egui::Ui, form: &mut ConnForm) {
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Usuario", |ui| {
        let width = ui.available_width();
        crate::ui::kit::text_input(ui, &mut form.user, width, "usuario del servidor", &mut form.errors.user);
        crate::ui::kit::error_line(ui, &form.errors.user);
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Autenticación", |ui| {
        ComboBox::from_id_salt("auth")
            .width(ui.available_width())
            .selected_text(match form.auth {
                Auth::Password => "Contraseña",
                Auth::Key => "Llave privada",
                Auth::Agent => "ssh-agent",
                Auth::Interactive => "Interactivo (2FA)",
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut form.auth, Auth::Agent, "ssh-agent");
                ui.selectable_value(&mut form.auth, Auth::Key, "Llave privada");
                ui.selectable_value(&mut form.auth, Auth::Password, "Contraseña");
                ui.selectable_value(&mut form.auth, Auth::Interactive, "Interactivo (2FA)");
            })
            .response
            .hand();
    });
    if form.auth == Auth::Key {
        ui.add_space(theme::space::ROW);
        crate::ui::kit::form_row(ui, "Llave privada", |ui| {
            let width = ui.available_width();
            crate::ui::kit::text_input(ui, &mut form.key_path, width, "~/.ssh/id_ed25519", &mut form.errors.key_path);
            crate::ui::kit::error_line(ui, &form.errors.key_path);
        });
    }
    if matches!(form.auth, Auth::Password | Auth::Key) {
        ui.add_space(theme::space::ROW);
        crate::ui::kit::form_row(ui, if form.auth == Auth::Password { "Contraseña" } else { "Passphrase" }, |ui| {
            let width = ui.available_width();
            crate::ui::kit::password_field(ui, &mut form.secret, &mut form.reveal_secret, "opcional: se guarda en el almacén", width);
        });
    }
}

pub(super) fn telnet_rows(ui: &mut egui::Ui, form: &mut ConnForm) {
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Codificación", |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            for (encoding, label) in Encoding::ALL {
                ui.selectable_value(&mut form.encoding, encoding, label);
            }
        });
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "Opciones", |ui| {
        crate::ui::kit::switch_labeled(ui, &mut form.negotiate, "Negociar Telnet (eco, tamaño de ventana y tipo de terminal)");
        if !form.negotiate {
            ui.label(RichText::new("Sin negociar es una conexión TCP simple: no se traducen Enter ni opciones.").small().color(theme::subtext()));
        }
    });
    ui.add_space(theme::space::ROW);
    crate::ui::kit::form_row(ui, "", |ui| {
        ui.label(RichText::new("Telnet no cifra: contraseñas y comandos viajan en texto claro.").small().color(theme::red()));
    });
}

/// Comando inicial y túneles, solo de SSH; se despliega solo si un túnel tiene un error.
pub(super) fn advanced_rows(ui: &mut egui::Ui, form: &mut ConnForm, connections: &[Connection], ssh: bool) {
    let shown = CollapsingHeader::new(RichText::new("Avanzado").color(theme::subtext()))
        .id_salt("conn-advanced")
        .open(Some(form.advanced_open))
        .show(ui, |ui| {
            ui.add_space(theme::space::ROW);
            crate::ui::kit::form_row(ui, "Servidor de salto", |ui| {
                let current = form
                    .jump
                    .and_then(|id| connections.iter().find(|c| c.id == Some(id)))
                    .map_or("Ninguno".to_string(), |c| c.name.clone());
                ComboBox::from_id_salt("jump")
                    .width(ui.available_width())
                    .selected_text(current)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut form.jump, None, "Ninguno");
                        for other in connections.iter().filter(|c| c.id != form.id) {
                            ui.selectable_value(&mut form.jump, other.id, other.name.as_str());
                        }
                    })
                    .response
                    .hand();
            });
            if !ssh {
                return;
            }
            ui.add_space(theme::space::ROW);
            crate::ui::kit::form_row(ui, "Comando inicial", |ui| {
                let width = ui.available_width();
                ui.add_sized(
                    [width, theme::height::FIELD],
                    TextEdit::singleline(&mut form.init_command)
                        .hint_text("opcional, se ejecuta al abrir la sesión")
                        .align(egui::Align2::LEFT_CENTER),
                );
            });
            ui.add_space(theme::space::GROUP);
            ui.label(RichText::new("Túneles (se activan al conectar)").small().color(theme::subtext()));
            let mut remove = None;
            form.errors.forwards.resize(form.forwards.len(), None);
            for (index, row) in form.forwards.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    ComboBox::from_id_salt(("fwd-kind", index))
                        .width(92.0)
                        .selected_text(match row.kind {
                            ForwardKind::Local => "Local -L",
                            ForwardKind::Remote => "Remoto -R",
                            ForwardKind::Dynamic => "SOCKS -D",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut row.kind, ForwardKind::Local, "Local -L");
                            ui.selectable_value(&mut row.kind, ForwardKind::Remote, "Remoto -R");
                            ui.selectable_value(&mut row.kind, ForwardKind::Dynamic, "SOCKS -D");
                        })
                        .response
                        .hand();
                    let broken = form.errors.forwards[index].is_some();
                    ui.scope(|ui| {
                        if broken {
                            let stroke = egui::Stroke::new(theme::stroke::MEDIUM, theme::red());
                            let widgets = &mut ui.visuals_mut().widgets;
                            widgets.inactive.bg_stroke = stroke;
                            widgets.hovered.bg_stroke = stroke;
                        }
                        ui.add(TextEdit::singleline(&mut row.bind_host).desired_width(86.0).hint_text("escucha"));
                        ui.add(TextEdit::singleline(&mut row.bind_port).desired_width(54.0).hint_text("puerto"));
                        if row.kind == ForwardKind::Dynamic {
                            ui.label(RichText::new("proxy SOCKS5").small().color(theme::subtext()));
                        } else {
                            ui.label("→");
                            ui.add(TextEdit::singleline(&mut row.dest_host).desired_width(86.0).hint_text("destino"));
                            ui.add(TextEdit::singleline(&mut row.dest_port).desired_width(54.0).hint_text("puerto"));
                        }
                    });
                    if ui.add(egui::Button::new(crate::ui::icons::X).frame(false)).on_hover_text("Quitar túnel").clicked() {
                        remove = Some(index);
                    }
                });
                if let Some(message) = &form.errors.forwards[index] {
                    let line = ui.label(RichText::new(message.as_str()).small().color(theme::red()));
                    if crate::ui::kit::take_reveal_error() {
                        line.scroll_to_me(Some(egui::Align::Center));
                    }
                } else if row.listens_on_network() {
                    ui.label(RichText::new("Escucha fuera de este equipo: otros dispositivos de la red podrán usar este túnel.").small().color(theme::identity(1)));
                }
            }
            if let Some(index) = remove {
                form.forwards.remove(index);
                form.errors.forwards.remove(index);
            }
            if crate::ui::kit::button_with(ui, egui::Button::new("+ Añadir túnel"), crate::ui::kit::Variant::Secondary).clicked() {
                form.forwards.push(ForwardRow::new());
                form.errors.forwards.push(None);
            }
            ui.label(
                RichText::new("-L: este equipo escucha y reenvía al destino vía el servidor. -R: el servidor escucha y reenvía a un destino alcanzable desde aquí. -D: proxy SOCKS5 local que sale por el servidor. Los cambios se aplican al reconectar.")
                    .small()
                    .color(theme::subtext()),
            );
        });
    if shown.header_response.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
        form.advanced_open = !form.advanced_open;
    }
}

pub(super) fn edit_body(ui: &mut egui::Ui, form: &mut ConnForm, connections: &[Connection]) -> bool {
    // Pantalla menos título, pie, márgenes y la línea de estado.
    let room = (ui.ctx().content_rect().height() * 0.9 - 38.0 - 56.0 - 34.0 - 34.0).max(240.0);
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        kind_list(ui, form);
        ui.vertical(|ui| {
            egui::Frame::NONE
                .inner_margin(egui::Margin { left: 18, right: 18, top: 16, bottom: 18 })
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(8.0, 4.0);
                    ScrollArea::vertical()
                        .max_height(room)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            // La barra flotante no debe tapar el borde de los campos.
                            ui.set_max_width(ui.available_width() - 10.0);
                            // Altura mínima para que el diálogo no salte al cambiar entre tipos de distinta longitud.
                            ui.set_min_height(380.0_f32.min(room));
                            form_fields(ui, form, connections)
                        })
                        .inner
                })
                .inner
        })
        .inner
    })
    .inner
}

pub(super) fn form_fields(ui: &mut egui::Ui, form: &mut ConnForm, connections: &[Connection]) -> bool {
    crate::ui::kit::form_row(ui, "Nombre", |ui| {
        let width = ui.available_width();
        let response = crate::ui::kit::text_input(ui, &mut form.name, width, "Nombre de la conexión", &mut form.errors.name);
        if std::mem::take(&mut form.focus) {
            response.request_focus();
        }
        crate::ui::kit::error_line(ui, &form.errors.name);
    });
    // El entorno va junto al nombre: es lo que evita escribir en el servidor equivocado.
    ui.add_space(theme::space::ROW);
    environment_row(ui, form);

    ui.add_space(theme::space::L);
    let kind = ConnKind::of(form);
    if kind == ConnKind::Local {
        local_rows(ui, form);
        return false;
    }
    if kind == ConnKind::Serial {
        serial_rows(ui, form);
        return false;
    }
    if kind == ConnKind::Adb {
        adb_rows(ui, form);
        return false;
    }
    if kind == ConnKind::Engine {
        engine_rows(ui, form, connections);
        return false;
    }
    crate::ui::kit::form_row(ui, "Servidor", |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let host_width = (ui.available_width() - 80.0 - 8.0).max(120.0);
            crate::ui::kit::text_input(ui, &mut form.host, host_width, "ejemplo.com o 10.0.0.5", &mut form.errors.host);
            crate::ui::kit::text_input(ui, &mut form.port, 80.0, "22", &mut form.errors.port);
        });
        crate::ui::kit::error_line(ui, &form.errors.host);
        crate::ui::kit::error_line(ui, &form.errors.port);
    });
    match kind {
        ConnKind::Ssh | ConnKind::Sftp => ssh_access_rows(ui, form),
        ConnKind::Ftp | ConnKind::Smb => files_rows(ui, form),
        ConnKind::Telnet => telnet_rows(ui, form),
        ConnKind::Serial | ConnKind::Adb | ConnKind::Local | ConnKind::Engine => {}
    }
    if matches!(kind, ConnKind::Ssh | ConnKind::Sftp) {
        ui.add_space(theme::space::GROUP);
        advanced_rows(ui, form, connections, kind == ConnKind::Ssh);
    }
    false
}
