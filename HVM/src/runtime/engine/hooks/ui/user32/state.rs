use super::*;

pub(super) const WH_MSGFILTER: i32 = -1;
pub(super) const MSGF_DIALOGBOX: i32 = 0;
pub(super) const USER32_MESSAGE_WAIT_POLL_MS: u32 = 10;
pub(super) const WM_NULL: u32 = 0x0000;
pub(super) const WM_QUIT: u32 = 0x0012;
pub(super) const WM_KEYDOWN: u32 = 0x0100;
pub(super) const WM_TIMER: u32 = 0x0113;
pub(super) const VK_RETURN: u32 = 0x000D;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct User32HookRecord {
    pub(super) handle: u32,
    pub(super) hook_type: i32,
    pub(super) callback: u64,
    pub(super) module_handle: u64,
    pub(super) thread_id: u32,
    pub(super) seeded: bool,
    pub(super) delivery_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct User32TimerRecord {
    pub(super) hwnd: u32,
    pub(super) timer_id: u32,
    pub(super) elapse_ms: u32,
    pub(super) callback: u64,
    pub(super) thread_id: u32,
    pub(super) next_due_tick: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct User32MessageRecord {
    pub(super) thread_id: u32,
    pub(super) hwnd: u64,
    pub(super) message: u32,
    pub(super) w_param: u64,
    pub(super) l_param: u64,
    pub(super) time: u32,
    pub(super) point_x: i32,
    pub(super) point_y: i32,
    pub(super) hook_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct User32ClassRecord {
    pub(super) atom: u16,
    pub(super) class_name: String,
    pub(super) wnd_proc: u64,
    pub(super) instance: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct User32WindowRecord {
    pub(super) handle: u32,
    pub(super) class_name: String,
    pub(super) wnd_proc: u64,
    pub(super) title: String,
    pub(super) parent: u32,
    pub(super) owner_thread: u32,
    pub(super) instance: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::runtime::engine) struct User32State {
    pub(super) desktop_window: Option<u32>,
    pub(super) active_window: Option<u32>,
    pub(super) shell_window: Option<u32>,
    pub(super) default_dc: Option<u32>,
    pub(super) default_icon: Option<u32>,
    pub(super) default_cursor: Option<u32>,
    pub(super) screen_width: i32,
    pub(super) screen_height: i32,
    pub(super) cursor_x: i32,
    pub(super) cursor_y: i32,
    pub(super) message_x: i32,
    pub(super) message_y: i32,
    pub(super) message_sequence: u32,
    pub(super) message_step_x: i32,
    pub(super) message_step_y: i32,
    pub(super) next_timer_id: u32,
    pub(super) next_class_atom: u16,
    pub(in crate::runtime::engine) get_message_calls: u64,
    pub(in crate::runtime::engine) peek_message_calls: u64,
    pub(in crate::runtime::engine) translate_message_calls: u64,
    pub(in crate::runtime::engine) dispatch_message_calls: u64,
    pub(in crate::runtime::engine) set_timer_calls: u64,
    pub(in crate::runtime::engine) kill_timer_calls: u64,
    pub(in crate::runtime::engine) synthetic_timer_messages: u64,
    pub(in crate::runtime::engine) synthetic_idle_messages: u64,
    pub(in crate::runtime::engine) hook_callback_dispatches: u64,
    pub(super) hooks: BTreeMap<u32, User32HookRecord>,
    pub(super) timers: BTreeMap<u32, User32TimerRecord>,
    pub(super) registered_classes: BTreeMap<String, User32ClassRecord>,
    pub(super) class_atoms: BTreeMap<u16, String>,
    pub(super) windows: BTreeMap<u32, User32WindowRecord>,
    pub(super) thread_messages: BTreeMap<u32, VecDeque<User32MessageRecord>>,
    pub(super) pending_hook_messages: BTreeMap<u32, VecDeque<User32MessageRecord>>,
}

impl Default for User32State {
    fn default() -> Self {
        Self {
            desktop_window: None,
            active_window: None,
            shell_window: None,
            default_dc: None,
            default_icon: None,
            default_cursor: None,
            screen_width: 1920,
            screen_height: 1080,
            cursor_x: 960,
            cursor_y: 540,
            message_x: 960,
            message_y: 540,
            message_sequence: 0,
            message_step_x: 0,
            message_step_y: 0,
            next_timer_id: 1,
            next_class_atom: 1,
            get_message_calls: 0,
            peek_message_calls: 0,
            translate_message_calls: 0,
            dispatch_message_calls: 0,
            set_timer_calls: 0,
            kill_timer_calls: 0,
            synthetic_timer_messages: 0,
            synthetic_idle_messages: 0,
            hook_callback_dispatches: 0,
            hooks: BTreeMap::new(),
            timers: BTreeMap::new(),
            registered_classes: BTreeMap::new(),
            class_atoms: BTreeMap::new(),
            windows: BTreeMap::new(),
            thread_messages: BTreeMap::new(),
            pending_hook_messages: BTreeMap::new(),
        }
    }
}

impl User32State {
    pub(in crate::runtime::engine) fn from_environment_profile(
        profile: &crate::environment_profile::EnvironmentProfile,
    ) -> User32State {
        fn maybe_handle(value: u32) -> Option<u32> {
            (value != 0).then_some(value)
        }

        User32State {
            desktop_window: maybe_handle(profile.display.desktop_window_handle),
            active_window: maybe_handle(profile.display.active_window_handle),
            shell_window: maybe_handle(profile.display.shell_window_handle),
            default_dc: maybe_handle(profile.display.default_dc_handle),
            default_icon: None,
            default_cursor: None,
            screen_width: profile.display.screen_width.max(1),
            screen_height: profile.display.screen_height.max(1),
            cursor_x: profile.display.cursor_x,
            cursor_y: profile.display.cursor_y,
            message_x: profile.display.message_x,
            message_y: profile.display.message_y,
            message_sequence: 0,
            message_step_x: profile.display.message_step_x,
            message_step_y: profile.display.message_step_y,
            next_timer_id: 1,
            next_class_atom: 1,
            get_message_calls: 0,
            peek_message_calls: 0,
            translate_message_calls: 0,
            dispatch_message_calls: 0,
            set_timer_calls: 0,
            kill_timer_calls: 0,
            synthetic_timer_messages: 0,
            synthetic_idle_messages: 0,
            hook_callback_dispatches: 0,
            hooks: BTreeMap::new(),
            timers: BTreeMap::new(),
            registered_classes: BTreeMap::new(),
            class_atoms: BTreeMap::new(),
            windows: BTreeMap::new(),
            thread_messages: BTreeMap::new(),
            pending_hook_messages: BTreeMap::new(),
        }
    }
}

impl VirtualExecutionEngine {
    pub(super) fn user32_current_thread_id(&self) -> u32 {
        self.scheduler
            .current_tid()
            .or(self.main_thread_tid)
            .unwrap_or(0)
    }

    pub(in crate::runtime::engine) fn user32_active_timer_count(&self) -> u64 {
        self.user32_state.timers.len() as u64
    }

    pub(in crate::runtime::engine) fn user32_active_hook_count(&self) -> u64 {
        self.user32_state.hooks.len() as u64
    }
}
