//! Cerrar pestañas, paneles y la ventana, con confirmación si hay algo en marcha.

use super::*;

impl App {
    /// Pestañas afectadas por una acción de cierre, y entre ellas las que tienen algo en marcha.
    pub(super) fn close_busy_lines(&self, action: CloseAction) -> Vec<String> {
        let affected: Vec<usize> = match action {
            CloseAction::Tab(id) => self.tabs.iter().position(|t| t.id == id).into_iter().collect(),
            CloseAction::Others(id) => (0..self.tabs.len()).filter(|i| self.tabs[*i].id != id).collect(),
            CloseAction::Right(id) => match self.tabs.iter().position(|t| t.id == id) {
                Some(position) => ((position + 1)..self.tabs.len()).collect(),
                None => Vec::new(),
            },
            CloseAction::Window => (0..self.tabs.len()).collect(),
        };
        affected
            .into_iter()
            .filter_map(|i| self.tabs[i].busy_reason().map(|reason| format!("«{}»: {reason}", self.tabs[i].title())))
            .collect()
    }

    /// Cierra directamente o, si hay algo en ejecución y no se ha desactivado, pide confirmación.
    pub(super) fn request_close(&mut self, action: CloseAction) {
        let lines = if self.settings.confirm_close { self.close_busy_lines(action) } else { Vec::new() };
        if lines.is_empty() {
            self.perform_close(action);
        } else if self.dialog.is_none() {
            self.dialog = Some(Dialog::ConfirmClose(CloseConfirm { action, lines, dont_ask: false }));
        }
    }

    pub(super) fn perform_close(&mut self, action: CloseAction) {
        match action {
            CloseAction::Tab(id) => {
                if let Some(position) = self.tabs.iter().position(|t| t.id == id) {
                    self.close_tab(position);
                }
            }
            CloseAction::Others(id) => {
                for index in (0..self.tabs.len()).rev() {
                    if self.tabs[index].id != id {
                        self.close_tab(index);
                    }
                }
                self.active = 0;
            }
            CloseAction::Right(id) => {
                if let Some(position) = self.tabs.iter().position(|t| t.id == id) {
                    for index in ((position + 1)..self.tabs.len()).rev() {
                        self.close_tab(index);
                    }
                    self.active = self.active.min(self.tabs.len().saturating_sub(1));
                }
            }
            CloseAction::Window => {
                self.close_confirmed = true;
                self.ctx.send_viewport_cmd(ViewportCommand::Close);
            }
        }
    }

    /// Pega en un panel concreto, si sigue abierto.
    pub(super) fn write_paste(&mut self, tab: u64, pane: u64, text: &str) {
        let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab) else { return };
        if let Body::Terminal { panes, .. } = &mut tab.body
            && let Some(pane) = panes.get_mut(pane)
        {
            pane.write_paste(text);
        }
    }

    pub(super) fn close_tab(&mut self, index: usize) {
        let tab = self.tabs.remove(index);
        self.container_shells.remove(&tab.id);
        if self.active >= self.tabs.len() {
            self.active = self.tabs.len().saturating_sub(1);
        } else if index < self.active {
            self.active -= 1;
        }
    }
}
