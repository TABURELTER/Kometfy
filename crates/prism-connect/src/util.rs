use std::{fs, io::Write, path::Path};

use serde_yaml::{Mapping, Value};

use crate::error::Result;

#[cfg_attr(not(windows), allow(dead_code))]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Write-temp-then-rename so a crash never leaves a half-written file.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn k(s: &str) -> Value {
    Value::String(s.to_string())
}

pub fn put(m: &mut Mapping, key: &str, v: impl Into<Value>) {
    m.insert(k(key), v.into());
}

pub fn strs<I, S>(it: I) -> Value
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Value::Sequence(it.into_iter().map(|s| Value::String(s.into())).collect())
}

pub fn str_of<'a>(m: &'a Mapping, key: &str) -> Option<&'a str> {
    m.get(key).and_then(Value::as_str)
}
