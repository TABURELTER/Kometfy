//! Single-instance guard (named mutex) and "bring the running window to front".

#[cfg(windows)]
mod platform {
use std::time::{Duration, Instant};

use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0},
    System::Threading::{CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE, INFINITE},
    UI::WindowsAndMessaging::{AllowSetForegroundWindow, FindWindowW, SetForegroundWindow, ShowWindow, ASFW_ANY, SW_RESTORE, SW_SHOW},
};

use crate::channel::NOW;

const MUTEX_NAME: &str = NOW.mutex;
const WINDOW_TITLE: &str = NOW.window_title;
/// Set by another launch: show the window. A start with Windows makes no window, so there may be none to find by title.
const SHOW_EVENT: &str = NOW.show_event;

/// Holds the mutex until the process exits. Never closed on purpose.
pub struct Guard(#[allow(dead_code)] HANDLE);
// SAFETY: a mutex handle is a plain kernel object id.
unsafe impl Send for Guard {}
unsafe impl Sync for Guard {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `wait` > 0 lets an elevated relaunch wait for the previous instance to finish exiting.
/// None = another instance owns it (a mutex we cannot open counts: an elevated instance made it).
pub fn acquire(wait: Duration) -> Option<Guard> {
    #[cfg(debug_assertions)]
    let mutex = if std::env::var_os("PRISM_UI_PREVIEW_DIR").is_some() {
        NOW.preview_mutex
    } else { MUTEX_NAME };
    #[cfg(not(debug_assertions))]
    let mutex = MUTEX_NAME;
    let name = wide(mutex);
    let start = Instant::now();
    loop {
        let h = unsafe { CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
        if !h.is_null() {
            if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
                return Some(Guard(h));
            }
            unsafe { CloseHandle(h) };
        }
        if start.elapsed() >= wait {
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

impl Guard {
    /// Give the mutex back so a process we are about to start can take it.
    pub fn release(self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// In the running instance: call `show` whenever another launch asks for the window.
pub fn on_show_request(show: impl Fn() + Send + 'static) {
    let name = wide(SHOW_EVENT);
    // auto-reset: one wake per request
    let h = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
    if h.is_null() {
        return;
    }
    let h = h as usize; // a kernel object id, valid for the whole process
    std::thread::spawn(move || {
        while unsafe { WaitForSingleObject(h as HANDLE, INFINITE) } == WAIT_OBJECT_0 {
            show();
        }
    });
}

/// Best effort: show and focus the window of the instance that is already running (it makes one if it has none).
pub fn focus_existing() {
    let name = wide(SHOW_EVENT);
    unsafe {
        let h = OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr());
        if !h.is_null() {
            // this launch has the user's click: let the running instance bring its window to the front
            AllowSetForegroundWindow(ASFW_ANY);
            SetEvent(h);
            CloseHandle(h);
        }
    }
    let title = wide(WINDOW_TITLE);
    unsafe {
        let hwnd = FindWindowW(std::ptr::null(), title.as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_SHOW);
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }
}
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{fs::{self, File, OpenOptions}, os::fd::AsRawFd, time::{Duration, Instant}};

    pub struct Guard(File);

    pub fn acquire(wait: Duration) -> Option<Guard> {
        let dir = std::env::var_os("HOME").map(std::path::PathBuf::from)?
            .join("Library/Application Support").join(crate::channel::NOW.data_dir);
        fs::create_dir_all(&dir).ok()?;
        let file = OpenOptions::new().read(true).write(true).create(true).open(dir.join("instance.lock")).ok()?;
        let start = Instant::now();
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Some(Guard(file));
            }
            if start.elapsed() >= wait { return None; }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    impl Guard {
        pub fn release(self) { drop(self); }
    }

    impl Drop for Guard {
        fn drop(&mut self) { unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN); } }
    }

    pub fn focus_existing() {
        let _ = std::process::Command::new("/usr/bin/open")
            .args(["-b", crate::channel::NOW.bundle_id]).spawn();
    }

    /// macOS brings the running app forward itself (`open -b`); its window is made at the start.
    pub fn on_show_request(_show: impl Fn() + Send + 'static) {}
}

/// A phone starts one copy of an app by itself: nothing to guard.
#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use std::time::Duration;

    pub struct Guard;

    pub fn acquire(_wait: Duration) -> Option<Guard> {
        Some(Guard)
    }

    impl Guard {
        pub fn release(self) {}
    }

    pub fn focus_existing() {}

    pub fn on_show_request(_show: impl Fn() + Send + 'static) {}
}

pub use platform::*;
