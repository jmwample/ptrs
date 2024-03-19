use crate::args::Args;

use std::{
    env,
    io::{Error, ErrorKind},
    net::SocketAddr,
};

use tokio::net::TcpStream;
use tracing::debug;
use url::Url;

pub(crate) fn get_managed_transport_ver() -> Result<String, Error> {
    Ok("".into())
}

// ================================================================ //
//                            Client                                //
// ================================================================ //

pub struct ClientInfo {
    pub methods: Vec<String>,
    pub uri: Option<Url>,
}

impl ClientInfo {
    pub fn new() -> Result<Self, Error> {
        let ver = get_managed_transport_ver()?;
        debug!("VERSION {ver}");

        Ok(Self {
            methods: get_client_transports()?,
            uri: get_proxy_url()?,
        })
    }
}

pub(crate) fn get_client_transports() -> Result<Vec<String>, Error> {
    Ok(vec![])
}

pub(crate) fn get_proxy_url() -> Result<Option<Url>, Error> {
    let url_str = match env::var("TOR_PT_PROXY") {
        Ok(s) => s,
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(e) => return Err(to_io_other(format!("failed to parse proxy config: {e}"))),
    };

    // Url::parse() only works for absolute urls so we do not need to check for relative
    let uri = Url::parse(&url_str)
        .map_err(|e| to_io_other(format!("failed to parse proxy config \"{url_str}\": {e}")))?;

    validate_proxy_url(&uri)?;

    Ok(Some(uri))
}

pub(crate) fn validate_proxy_url(spec: &Url) -> Result<(), Error> {
    if !spec.path().is_empty() {
        return Err(to_io_other("proxy URI has a path defined"));
    }
    if spec.query().is_some_and(|s| !s.is_empty()) {
        return Err(to_io_other("proxy URI has a query defined"));
    }
    if spec.fragment().is_some_and(|s| !s.is_empty()) {
        return Err(to_io_other("proxy URI has a fragment defined"));
    }

    match spec.scheme() {
        "socks5" => {
            let username = spec.username();
            let passwd = spec.password();

            if username.is_empty() || username.len() > 255 {
                return Err(to_io_other("proxy URI specified a invalid SOCKS5 username"));
            }
            if passwd.is_none() || passwd.is_some_and(|p| p.is_empty() || p.len() > 255) {
                return Err(to_io_other("proxy URI specified a invalid SOCKS5 password"));
            }
        }
        "socks4a" => {
            if !spec.username().is_empty() && spec.password().is_some_and(|p| !p.is_empty()) {
                return Err(to_io_other("proxy URI specified SOCKS4a and a password"));
            }
        }
        "http" => {}
        _ => {
            return Err(to_io_other(format!(
                "proxy URI has invalid scheme: {}",
                spec.scheme()
            )));
        }
    }

    _ = resolve_addr(spec.host_str())
        .map_err(|e| to_io_other(format!("proxy URI has invalid host: {e}")))?;

    Ok(())
}

// ================================================================ //
//                            Server                                //
// ================================================================ //

/// Check the server pluggable transports environment, emitting an error message
/// and returning a non-nil error if any error is encountered. Resolves the
/// various requested bind addresses, the server ORPort and extended ORPort, and
/// reads the auth cookie file. Returns a ServerInfo struct.
///
/// If your program needs to know whether to call ClientSetup or ServerSetup
/// (i.e., if the same program can be run as either a client or a server), check
/// whether the `TOR_PT_CLIENT_TRANSPORTS` environment variable is set:
///
/// ```
/// match std::env::var_os("TOR_PT_CLIENT_TRANSPORTS") {
///     Some(_) => {
///         // Client mode; call pt.ClientSetup.
///     }
///     None => {
///         // Server mode; call pt.ServerSetup.
///     }
/// }
///```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ServerInfo {
    pub bind_addrs: Vec<Bindaddr>,
    pub or_addr: Option<SocketAddr>,
    pub extended_or_addr: Option<SocketAddr>,
    pub auth_cookie_path: Option<String>,
}

impl ServerInfo {
    pub async fn connect_to_or(&self) -> Result<TcpStream, Error> {
        let conn = match self.or_addr {
            Some(addr) => TcpStream::connect(addr).await?,
            None => {
                if self.extended_or_addr.is_none() {
                    return Err(to_io_other("no OR addr provided"));
                }

                TcpStream::connect(self.extended_or_addr.unwrap()).await?
            }
        };

        Ok(conn)
    }
}

impl ServerInfo {
    pub fn new() -> Result<Self, Error> {
        let ver = get_managed_transport_ver()?;
        debug!("VERSION {ver}");

        let bind_addrs = Bindaddr::get_server_bind_addrs()?;

        let or_add_env = env::var_os("TOR_PT_ORPORT").map(|s| s.into_string().unwrap());
        let or_addr = resolve_addr(or_add_env)
            .map_err(|e| to_io_other(format!("cannot resolve TOR_PT_ORPORT: {e}")))?;

        let auth_cookie_path = env::var("TOR_PT_AUTH_COOKIE_FILE").ok();

        let ext_or_addr_env =
            env::var_os("TOR_PT_EXTENDED_SERVER_PORT").map(|s| s.into_string().unwrap());

        if ext_or_addr_env.clone().is_some_and(|s| !s.is_empty()) && auth_cookie_path.is_none() {
            return Err(to_io_other("need TOR_PT_AUTH_COOKIE_FILE environment variable with TOR_PT_EXTENDED_SERVER_PORT"));
        }

        let extended_or_addr = resolve_addr(ext_or_addr_env)
            .map_err(|e| to_io_other(format!("cannot resolve TOR_PT_EXTENDED_SERVER_PORT: {e}")))?;

        // Need either OrAddr or ExtendedOrAddr.
        if or_addr.is_none() && extended_or_addr.is_none() {
            return Err(to_io_other(
                "need TOR_PT_ORPORT or TOR_PT_EXTENDED_SERVER_PORT environment variable",
            ));
        }

        Ok(Self {
            bind_addrs,
            or_addr,
            extended_or_addr,
            auth_cookie_path,
        })
    }
}

/// A combination of a method name and an address, as extracted from `TOR_PT_SERVER_BINDADDR`.
#[derive(Clone, Debug, PartialEq)]
pub struct Bindaddr {
    pub method_name: String,
    pub addr: SocketAddr,
    // Options from TOR_PT_SERVER_TRANSPORT_OPTIONS that pertain to this
    // transport.
    pub options: Args,
}

impl Bindaddr {
    pub(crate) fn get_server_bind_addrs() -> Result<Vec<Self>, Error> {
        Ok(vec![])
    }
}

pub fn resolve_addr(_addr: Option<impl AsRef<str>>) -> Result<Option<SocketAddr>, Error> {
    Ok(None)
}

fn to_io_other(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Other, format!("{e}"))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::args::Opts;

    #[test]
    fn get_server_info() -> Result<(), Error> {
        let si = ServerInfo::new()?;
        assert!(si.auth_cookie_path.is_none());

        Ok(())
    }

    #[test]
    fn get_client_info() -> Result<(), Error> {
        let ci = ClientInfo::new()?;
        assert!(ci.uri.is_none());
        assert!(!ci.methods.is_empty());

        Ok(())
    }

    #[test]
    fn resolve() -> Result<(), Error> {
        let res = resolve_addr(None::<String>).unwrap();
        assert!(res.is_none());

        let res = resolve_addr(Some("127.0.0.1:8000")).unwrap();
        assert!(res.is_some_and(|a| a == "127.0.0.1:8000".parse().unwrap()));

        Ok(())
    }

    #[test]
    fn smethod_args() -> Result<(), Error> {
        let args = Opts::parse_server_transport_options("").map_err(to_io_other)?;
        assert!(!args.is_empty());

        Ok(())
    }

    #[test]
    fn validate_url() -> Result<(), Error> {
        let url = validate_proxy_url(&Url::parse("socks5://example.com/").unwrap());
        assert!(url.is_ok());

        Ok(())
    }
}
