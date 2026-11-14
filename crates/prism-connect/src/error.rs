use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
    /// Machine-readable codes: the UI maps these to localized messages.
    #[error("NEED_ADMIN")]
    NeedAdmin,
    #[error("CORE_MISSING")]
    CoreMissing,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// `reqwest` hides the real reason ("dns error", "connection reset", certificate problems) a few
/// levels down, and puts the URL (often a secret subscription token) in the message. Show the
/// cause chain, never the URL.
impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        let e = e.without_url();
        let mut msg = e.to_string();
        let mut src = std::error::Error::source(&e);
        while let Some(s) = src {
            let part = s.to_string();
            if !msg.contains(&part) {
                msg.push_str(": ");
                msg.push_str(&part);
            }
            src = s.source();
        }
        Error::Msg(msg)
    }
}

impl Error {
    pub fn msg(m: impl Into<String>) -> Self {
        Self::Msg(m.into())
    }
}
