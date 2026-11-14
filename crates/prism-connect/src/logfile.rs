//! The app's log file with a size limit: when it grows past `max`, it moves to `name.1`, the old
//! `name.1` to `name.2`, and so on; the oldest file is deleted. The disk never holds more than
//! `keep + 1` files of about `max` bytes each.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

pub struct RotatingLog {
    path: PathBuf,
    file: Option<File>,
    written: u64,
    max: u64,
    keep: usize,
}

impl RotatingLog {
    /// Opens (or creates) `path` for appending. A file that is already over the limit rotates at once.
    pub fn open(path: PathBuf, max: u64, keep: usize) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut log = Self { path, file: None, written: 0, max, keep };
        log.written = fs::metadata(&log.path).map_or(0, |m| m.len());
        if log.written >= log.max {
            log.rotate()?;
        } else {
            log.file = Some(OpenOptions::new().create(true).append(true).open(&log.path)?);
        }
        Ok(log)
    }

    fn numbered(&self, n: usize) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file = None; // Windows will not rename a file that is still open
        if self.keep == 0 {
            let _ = fs::remove_file(&self.path);
        } else {
            let _ = fs::remove_file(self.numbered(self.keep));
            for n in (1..self.keep).rev() {
                let _ = fs::rename(self.numbered(n), self.numbered(n + 1));
            }
            let _ = fs::rename(&self.path, self.numbered(1));
        }
        self.file = Some(OpenOptions::new().create(true).append(true).open(&self.path)?);
        self.written = 0;
        Ok(())
    }
}

impl Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u64 > self.max && self.written > 0 {
            self.rotate()?;
        }
        let file = self.file.as_mut().ok_or_else(|| io::Error::other("log file is closed"))?;
        let n = file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), Write::flush)
    }
}

/// The last `lines` lines of `path` (and of its `.1` neighbour when the file is short), oldest first.
/// Reads at most about 256 KiB: a log is never loaded whole.
pub fn tail(path: &Path, lines: usize) -> Vec<String> {
    const WINDOW: u64 = 256 * 1024;
    let read = |p: &Path| -> Vec<String> {
        let Ok(mut f) = File::open(p) else { return Vec::new() };
        let len = f.metadata().map_or(0, |m| m.len());
        let skip = len.saturating_sub(WINDOW);
        if io::Seek::seek(&mut f, io::SeekFrom::Start(skip)).is_err() {
            return Vec::new();
        }
        let mut raw = Vec::new();
        let _ = io::Read::read_to_end(&mut f, &mut raw);
        let text = String::from_utf8_lossy(&raw);
        let mut all: Vec<String> = text.lines().map(str::to_owned).collect();
        if skip > 0 && !all.is_empty() {
            all.remove(0); // cut in the middle of a line
        }
        all
    };
    let mut out = read(path);
    if out.len() < lines {
        let mut name = path.as_os_str().to_owned();
        name.push(".1");
        let mut older = read(Path::new(&name));
        older.append(&mut out);
        out = older;
    }
    let from = out.len().saturating_sub(lines);
    out.split_off(from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("prism-log-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_log_never_outgrows_its_limit() {
        let d = dir("limit");
        let path = d.join("app.log");
        let mut log = RotatingLog::open(path.clone(), 1_000, 2).unwrap();
        for i in 0..400 {
            // one write per line, as the tracing writer does
            log.write_all(format!("line {i:04} {}\n", "x".repeat(40)).as_bytes()).unwrap();
        }
        log.flush().unwrap();
        let size = |p: &Path| fs::metadata(p).map_or(0, |m| m.len());
        assert!(size(&path) <= 1_000);
        assert!(size(&d.join("app.log.1")) <= 1_000);
        assert!(size(&d.join("app.log.2")) <= 1_000);
        assert!(!d.join("app.log.3").exists());
        // the newest line is in the live file, the oldest ones are gone
        assert!(fs::read_to_string(&path).unwrap().contains("line 0399"));
        let all: String = ["app.log", "app.log.1", "app.log.2"].iter().filter_map(|n| fs::read_to_string(d.join(n)).ok()).collect();
        assert!(!all.contains("line 0000"));
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn an_oversized_file_rotates_when_opened() {
        let d = dir("open");
        let path = d.join("app.log");
        fs::write(&path, "x".repeat(5_000)).unwrap();
        let mut log = RotatingLog::open(path.clone(), 1_000, 1).unwrap();
        log.write_all(b"fresh\n").unwrap();
        log.flush().unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "fresh\n");
        assert_eq!(fs::metadata(d.join("app.log.1")).unwrap().len(), 5_000);
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn the_tail_is_the_last_lines_in_order() {
        let d = dir("tail");
        let path = d.join("app.log");
        fs::write(d.join("app.log.1"), "old1\nold2\n").unwrap();
        fs::write(&path, "a\nb\nc\n").unwrap();
        assert_eq!(tail(&path, 2), ["b", "c"]);
        assert_eq!(tail(&path, 4), ["old2", "a", "b", "c"]);
        assert!(tail(&d.join("missing.log"), 3).is_empty());
        let _ = fs::remove_dir_all(d);
    }
}
