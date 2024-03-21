use crate::args::Args;

use std::{
    env,
    fs::DirBuilder,
    io::{Error, ErrorKind},
    net::SocketAddr,
    os::unix::fs::DirBuilderExt,
    str::FromStr,
};

use itertools::Itertools;
use tokio::net::TcpStream;
use tracing::debug;
use url::Url;

pub mod constants {
    pub const CURRENT_TRANSPORT_VER: &str = "1";

    pub const MANAGED_VER: &str = "TOR_PT_MANAGED_TRANSPORT_VER";
    pub const STATE_LOCATION: &str = "TOR_PT_STATE_LOCATION";
    pub const CLIENT_TRANSPORTS: &str = "TOR_PT_CLIENT_TRANSPORTS";
    pub const PROXY: &str = "TOR_PT_PROXY";
    pub const SERVER_TRANSPORTS: &str = "TOR_PT_SERVER_TRANSPORTS";
    pub const SERVER_TRANSPORT_OPTIONS: &str = "TOR_PT_SERVER_TRANSPORT_OPTIONS";
    pub const SERVER_BINDADDR: &str = "TOR_PT_SERVER_BINDADDR";
    pub const AUTH_COOKIE_FILE: &str = "TOR_PT_AUTH_COOKIE_FILE";
    pub const ORPORT: &str = "TOR_PT_ORPORT";
    pub const EXTENDED_SERVER_PORT: &str = "TOR_PT_EXTENDED_SERVER_PORT";
    pub const EXIT_ON_STDIN_CLOSE: &str = "TOR_PT_EXIT_ON_STDIN_CLOSE";
}

/// Get a pluggable transports version offered by Tor and understood by us, if
/// any. The only version we understand is "1". This function reads the
/// environment variable `TOR_PT_MANAGED_TRANSPORT_VER`.
pub(crate) fn get_managed_transport_ver() -> Result<String, Error> {
    let managed_transport_ver = env::var(constants::MANAGED_VER).map_err(to_io_other)?;
    for segment in managed_transport_ver.split(',') {
        if segment == constants::CURRENT_TRANSPORT_VER {
            return Ok(segment.into());
        }
    }

    Err(to_io_other("no-version"))
}

pub fn is_client() -> Result<bool, Error> {
    let is_client = env::var_os(constants::CLIENT_TRANSPORTS);
    let is_server = env::var_os(constants::SERVER_TRANSPORTS);

    match (is_client, is_server) {
        (Some(_), Some(_)) => Err(to_io_other(
            "ENV-ERROR TOR_PT_[CLIENT,SERVER]_TRANSPORTS both set",
        )),
        (Some(_), None) => Ok(true),
        (None, Some(_)) => Ok(false),
        (None, None) => Err(to_io_other("not launched as a managed transport")),
    }
}

/// Return the directory name in the TOR_PT_STATE_LOCATION environment variable,
/// creating it if it doesn't exist. Returns non-nil error if
/// `TOR_PT_STATE_LOCATION` is not set or if there is an error creating the
/// directory.
pub fn make_state_dir() -> Result<String, Error> {
    let path = env::var(constants::STATE_LOCATION)
        .map_err(|_| to_io_other("missing required TOR_PT_STATE_LOCATION env var"))?;

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&path)?;
    Ok(path)
}

/// Feature #15435 adds a new env var for determining if Tor keeps stdin
/// open for use in termination detection.
pub fn pt_should_exit_on_stdin_close() -> bool {
    env::var(constants::EXIT_ON_STDIN_CLOSE).is_ok_and(|v| v == "1")
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
    let client_transports = env::var(constants::CLIENT_TRANSPORTS).map_err(to_io_other)?;
    Ok(client_transports
        .split(',')
        .map(|s| String::from(s))
        .collect_vec())
}

pub(crate) fn get_proxy_url() -> Result<Option<Url>, Error> {
    let url_str = match env::var(constants::PROXY) {
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

        let bind_addrs = Bindaddr::get_server_bindaddrs()?;

        let or_add_env = env::var_os(constants::ORPORT).map(|s| s.into_string().unwrap());
        let or_addr = resolve_addr(or_add_env)
            .map_err(|e| to_io_other(format!("cannot resolve TOR_PT_ORPORT: {e}")))?;

        let auth_cookie_path = env::var(constants::AUTH_COOKIE_FILE).ok();

        let ext_or_addr_env =
            env::var_os(constants::EXTENDED_SERVER_PORT).map(|s| s.into_string().unwrap());

        if ext_or_addr_env.clone().is_some_and(|s| !s.is_empty()) && auth_cookie_path.is_none() {
            return Err(to_io_other("need TOR_PT_AUTH_COOKIE_FILE environment variable with TOR_PT_EXTENDED_SERVER_PORT"));
        }

        // let _cookie = match auth_cookie_path {
        //     Some(path) => Some(read_auth_cookie_file(path)?),
        //     None => None,
        // };

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
    pub(crate) fn get_server_bindaddrs() -> Result<Vec<Self>, Error> {
        todo!()
        // Ok(vec![])
    }
}

fn read_auth_cookie(_reader: impl std::io::Read) -> Result<[u8; 32], Error> {
    todo!()
}

/// Read and validate the contents of an auth cookie file. Returns the 32-byte
/// cookie. See section 2.1.2 of ext-orport-spec.txt.
fn read_auth_cookie_file(filename: impl AsRef<str>) -> Result<[u8; 32], Error> {
    let f = std::fs::File::open(filename.as_ref())?;
    read_auth_cookie(&f)
}

pub fn resolve_addr(addr: Option<impl AsRef<str>>) -> Result<Option<SocketAddr>, Error> {
    if addr.is_none() {
        return Ok(None);
    }
    let a_ref = addr.unwrap();
    let a = a_ref.as_ref();

    match SocketAddr::from_str(a) {
        Ok(sock_addr) => {
            if sock_addr.ip().is_unspecified() {
                return Err(to_io_other(format!("address string {a} lacks a host")));
            }

            if sock_addr.port() == 0 {
                return Err(to_io_other(format!("address string {a} lacks a port")));
            }
            Ok(Some(sock_addr))
        }
        Err(e) => Err(to_io_other(e)),
    }
}

fn to_io_other(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Other, format!("{e}"))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::args::Opts;

    #[test]
    fn server_bindaddrs() -> Result<(), Error> {
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
        let good: Vec<(Option<&str>, Option<SocketAddr>)> = vec![
            (None, None),
            (
                Some("127.0.0.1:8080"),
                Some("127.0.0.1:8080".parse().unwrap()),
            ),
            (
                Some("[1234::cdef]:9000"),
                Some("[1234::cdef]:9000".parse().unwrap()),
            ),
        ];

        for trial in good {
            let res = resolve_addr(trial.0).unwrap();
            assert_eq!(res, trial.1);
        }

        let bad = vec![
            "www.google.com", // not a socket address (domain)
            "google.com:443", // not a socket address (domain)
            "127.0.0",        // not an address
            "127.0.0.1",      // no port specified
            "127.0.0.1:",     // no port specified
            "127.0.0.1:0",    // no port specified
            "[1234::cdef]",   // no port specified
            "[1234::cdef]:",  // no port specified
            "[1234::cdef]:0", // no port specified
            ":9000",          // no address specified
        ];

        for trial in bad {
            assert!(resolve_addr(Some(trial)).is_err());
        }
        Ok(())
    }

    #[test]
    fn managed_ver() -> Result<(), Error> {
        // contains ver
        env::set_var(constants::MANAGED_VER, "3,2,1");
        assert_eq!(get_managed_transport_ver()?, "1");

        // contains ver
        env::set_var(constants::MANAGED_VER, "3,1,2");
        assert_eq!(get_managed_transport_ver()?, "1");

        // doesn't contains ver
        env::set_var(constants::MANAGED_VER, "3,2");
        assert!(get_managed_transport_ver().is_err());

        Ok(())
    }
}
