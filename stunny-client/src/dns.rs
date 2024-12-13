#![allow(dead_code)]
use std::io;
use std::net::SocketAddr;

const URI_PREFIX: &str = "stun:";
const URI_SECURE_PREFIX: &str = "stuns:";

pub(crate) async fn resolve_uri(uri: impl AsRef<str>) -> io::Result<Vec<SocketAddr>> {
    let uri = uri
        .as_ref()
        .strip_prefix(URI_PREFIX)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stun URI prefix missing"))?;

    let uri = if has_port(uri) {
        uri.to_owned()
    } else {
        format!("{uri}:3478")
    };
    let addrs: Vec<_> = tokio::net::lookup_host(uri).await?.collect();
    if addrs.is_empty() {
        Err(io::Error::from(io::ErrorKind::HostUnreachable))
    } else {
        Ok(addrs)
    }
}

pub(crate) async fn resolve_secure_uri(uri: impl AsRef<str>) -> io::Result<Vec<SocketAddr>> {
    let uri = uri
        .as_ref()
        .strip_prefix(URI_SECURE_PREFIX)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stuns URI prefix missing"))?;

    let uri = if has_port(uri) {
        uri.to_owned()
    } else {
        format!("{uri}:5349")
    };
    let addrs: Vec<_> = tokio::net::lookup_host(uri).await?.collect();
    if addrs.is_empty() {
        Err(io::Error::from(io::ErrorKind::HostUnreachable))
    } else {
        Ok(addrs)
    }
}

fn has_port(uri: &str) -> bool {
    uri.rsplit_once(':')
        .and_then(|(_hostname, port)| port.parse::<u16>().ok())
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_stun_uri() {
        let uri = "stun:stun.l.google.com:19302";

        assert!(resolve_secure_uri(uri).await.is_err());
        let addrs = resolve_uri(uri).await.unwrap();
        assert!(addrs
            .into_iter()
            .all(|socket_addr| socket_addr.port() == 19302));

        let uri = "stun:stunserver2024.stunprotocol.org";

        assert!(resolve_secure_uri(uri).await.is_err());
        let addrs = resolve_uri(uri).await.unwrap();
        assert!(addrs
            .into_iter()
            .all(|socket_addr| socket_addr.port() == 3478));
    }

    #[tokio::test]
    async fn resolve_secure_stun_uri() {
        let uri = "stuns:stun.l.google.com:19302";

        assert!(resolve_uri(uri).await.is_err());
        let addrs = resolve_secure_uri(uri).await.unwrap();
        assert!(addrs
            .into_iter()
            .all(|socket_addr| socket_addr.port() == 19302));

        let uri = "stuns:stunserver2024.stunprotocol.org";

        assert!(resolve_uri(uri).await.is_err());
        let addrs = resolve_secure_uri(uri).await.unwrap();
        assert!(addrs
            .into_iter()
            .all(|socket_addr| socket_addr.port() == 5349));
    }
}
