//! Encrypted Happ links: `happ://crypt4/<base64>`. The subscription address is encrypted with
//! Happ's RSA-4096 public key (PKCS#1 v1.5), so the app that adds the link cannot show it.
//! Only a Happ build with crypt4 support understands the result.
//!
//! The key is the one Remnawave and other panels ship for crypt4. It is public by design: it can
//! only lock, never open. (The key printed on happ.su's page belongs to the older crypt3.)

use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::{pkcs8::DecodePublicKey, rand_core::OsRng, Pkcs1v15Encrypt, RsaPublicKey};

use crate::error::{Error, Result};

pub const PREFIX: &str = "happ://crypt4/";

const CRYPT4_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3UZ0M3L4K+WjM3vkbQnz
ozHg/cRbEXvQ6i4A8RVN4OM3rK9kU01FdjyoIgywve8OEKsFnVwERZAQZ1Trv60B
hmaM76QQEE+EUlIOL9EpwKWGtTL5lYC1sT9XJMNP3/CI0gP5wwQI88cY/xedpOEB
W72EmOOShHUm/b/3m+HPmqwc4ugKj5zWV5SyiT829aFA5DxSjmIIFBAms7DafmSq
LFTYIQL5cShDY2u+/sqyAw9yZIOoqW2TFIgIHhLPWek/ocDU7zyOrlu1E0SmcQQb
LFqHq02fsnH6IcqTv3N5Adb/CkZDDQ6HvQVBmqbKZKf7ZdXkqsc/Zw27xhG7OfXC
tUmWsiL7zA+KoTd3avyOh93Q9ju4UQsHthL3Gs4vECYOCS9dsXXSHEY/1ngU/hjO
WFF8QEE/rYV6nA4PTyUvo5RsctSQL/9DJX7XNh3zngvif8LsCN2MPvx6X+zLouBX
zgBkQ9DFfZAGLWf9TR7KVjZC/3NsuUCDoAOcpmN8pENBbeB0puiKMMWSvll36+2M
YR1Xs0MgT8Y9TwhE2+TnnTJOhzmHi/BxiUlY/w2E0s4ax9GHAmX0wyF4zeV7kDkc
vHuEdc0d7vDmdw0oqCqWj0Xwq86HfORu6tm1A8uRATjb4SzjTKclKuoElVAVa5Jo
oh/uZMozC65SmDw+N5p6Su8CAwEAAQ==
-----END PUBLIC KEY-----";

fn encrypt_link(pem: &str, url: &str) -> Result<String> {
    let url = url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(Error::msg("only a subscription link (http:// or https://) can be encrypted"));
    }
    let key = RsaPublicKey::from_public_key_pem(pem).map_err(|e| Error::msg(format!("bad Happ key: {e}")))?;
    // PKCS#1 v1.5 leaves 11 bytes of the block for padding
    let room = rsa::traits::PublicKeyParts::size(&key) - 11;
    if url.len() > room {
        return Err(Error::msg(format!("the link is too long to encrypt ({} of {room} bytes)", url.len())));
    }
    let sealed = key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, url.as_bytes())
        .map_err(|e| Error::msg(format!("encryption failed: {e}")))?;
    Ok(format!("{PREFIX}{}", STANDARD.encode(sealed)))
}

/// `https://sub.example.com/abc` -> `happ://crypt4/...`
pub fn crypt4(url: &str) -> Result<String> {
    encrypt_link(CRYPT4_KEY, url)
}

/// Wrappers other apps put around a plain subscription link: the address comes out.
/// `happ://add/<url>`, `v2raytun://import/<url>`, `kometfy://import/<url>` (or `kometfy://add/<url>`)
/// and `kometfy://import?url=<percent-encoded url>`. Input without one of these schemes gives None.
/// Encrypted links (`happ://crypt...`) hide the address on purpose and are refused with the code
/// `HAPP_ENCRYPTED`.
pub fn unwrap(input: &str) -> Result<Option<String>> {
    // ASCII-only comparison: lower-casing the whole input could move byte offsets
    let rest = |prefix: &str| input.get(..prefix.len()).filter(|p| p.eq_ignore_ascii_case(prefix)).map(|_| &input[prefix.len()..]);
    if ["happ://", "v2raytun://", "kometfy://"].iter().all(|s| rest(s).is_none()) {
        return Ok(None);
    }
    if rest("happ://crypt").is_some() {
        return Err(Error::msg("HAPP_ENCRYPTED"));
    }
    let url = ["happ://add/", "v2raytun://import/", "kometfy://import/", "kometfy://add/"]
        .iter()
        .find_map(|w| rest(w))
        .map(str::to_string)
        .or_else(|| {
            let query = rest("kometfy://import?")?;
            let v = query.split('&').find_map(|kv| kv.strip_prefix("url="))?;
            Some(percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned())
        })
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    url.map(Some).ok_or_else(|| Error::msg("this link cannot be imported"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{pkcs8::EncodePublicKey, traits::PublicKeyParts, RsaPrivateKey};

    #[test]
    fn happ_key_is_a_4096_bit_rsa_key() {
        let key = RsaPublicKey::from_public_key_pem(CRYPT4_KEY).unwrap();
        assert_eq!(key.size(), 512);
    }

    #[test]
    fn happ_wrappers_are_opened_and_encrypted_links_refused() {
        assert_eq!(unwrap("https://a.example/b").unwrap(), None);
        assert_eq!(unwrap("vless://x@y:1").unwrap(), None);
        assert_eq!(
            unwrap("happ://add/https://sub.example.com/x?y=1").unwrap().as_deref(),
            Some("https://sub.example.com/x?y=1")
        );
        assert_eq!(unwrap("HAPP://crypt4/AAAA").unwrap_err().to_string(), "HAPP_ENCRYPTED");
        assert_eq!(unwrap("happ://crypt5/AAAA").unwrap_err().to_string(), "HAPP_ENCRYPTED");
        assert!(unwrap("happ://routing/xyz").is_err());
        assert!(unwrap("happ://add/").is_err());
    }

    #[test]
    fn other_wrappers_are_opened_too() {
        let url = Some("https://sub.example.com/x?y=1");
        assert_eq!(unwrap("v2raytun://import/https://sub.example.com/x?y=1").unwrap().as_deref(), url);
        assert_eq!(unwrap("kometfy://import/https://sub.example.com/x?y=1").unwrap().as_deref(), url);
        assert_eq!(unwrap("Kometfy://add/https://sub.example.com/x?y=1").unwrap().as_deref(), url);
        assert_eq!(unwrap("kometfy://import?name=a&url=https%3A%2F%2Fsub.example.com%2Fx%3Fy%3D1").unwrap().as_deref(), url);
        assert!(unwrap("kometfy://import?name=a").is_err());
        assert!(unwrap("kometfy://crypt/AAAA").is_err());
        assert!(unwrap("v2raytun://other").is_err());
        assert_eq!(unwrap("\u{212A}ometfy://import/x").unwrap(), None, "not ASCII: not our scheme");
    }

    #[test]
    fn link_has_the_crypt4_shape() {
        let link = crypt4("https://sub.example.com/abc?x=1").unwrap();
        let body = link.strip_prefix(PREFIX).unwrap();
        assert_eq!(STANDARD.decode(body).unwrap().len(), 512, "one RSA-4096 block");
        assert_ne!(link, crypt4("https://sub.example.com/abc?x=1").unwrap(), "padding is random");
        assert!(crypt4("vless://x@y:1").is_err());
        assert!(crypt4(&format!("https://e.com/{}", "a".repeat(600))).is_err());
    }

    /// With a key pair of our own the whole path can be opened again: what goes in comes out.
    #[test]
    fn the_address_comes_back_with_the_matching_private_key() {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = private.to_public_key().to_public_key_pem(Default::default()).unwrap();
        let url = "https://sub.example.com/s/abcDEF123?name=%D0%A2";
        let link = encrypt_link(&pem, &format!("  {url}\n")).unwrap();
        let sealed = STANDARD.decode(link.strip_prefix(PREFIX).unwrap()).unwrap();
        let plain = private.decrypt(Pkcs1v15Encrypt, &sealed).unwrap();
        assert_eq!(String::from_utf8(plain).unwrap(), url);
    }
}
