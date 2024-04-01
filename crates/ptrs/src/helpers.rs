use crate::{
    args::{Args, Opts},
    debug,
};

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

/// Determines if the current program should be running as a client or server
/// by checking the `TOR_PT_CLIENT_TRANSPORTS` and `TOR_PT_SERVER_TRANSPORTS`
/// environment variables.
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
        let _ver = get_managed_transport_ver()?;
        debug!("VERSION {_ver}");

        Ok(Self {
            methods: get_client_transports()?,
            uri: get_proxy_url()?,
        })
    }
}

pub(crate) fn get_client_transports() -> Result<Vec<String>, Error> {
    let client_transports = env::var(constants::CLIENT_TRANSPORTS).map_err(to_io_other)?;
    Ok(client_transports.split(',').map(String::from).collect_vec())
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

/// When a client connects to the client side of the pluggable transport proxy
/// they can optionally provide a proxy url in the `TOR_PT_PROXY` environment
/// variable that will be used as a proxy dialer underneath the pluggable
/// transport connection.
///
/// This function validates that a provided url:
/// - uses one of `socks4a`, `socks5`, `http` protocols.
/// - has a defined host field that DOES NOT require dns resolution. (i.e. an IP address)
/// - DOES NOT have defined `path`, `query`, or `fragment` fields.
/// - socks5 urls must have non-empty username and password fields.
/// - if socks4 urls have a password they must have a username.
///
/// From `pt-spec.txt 3.5`:
///
/// ```
///    On the client side, arguments are passed via the authentication
///    fields that are part of the SOCKS protocol.
///
///    ... The arguments are transmitted when making the outgoing
///    connection using the authentication mechanism specific to the
///    SOCKS protocol version.
///
///     - In the case of SOCKS 4, the concatenated argument list is
///       transmitted in the "USERID" field of the "CONNECT" request.
///
///     - In the case of SOCKS 5, the parent process must negotiate
///       "Username/Password" authentication [RFC1929], and transmit
///       the arguments encoded in the "UNAME" and "PASSWD" fields.
///
///       If the encoded argument list is less than 255 bytes in
///       length, the "PLEN" field must be set to "1" and the "PASSWD"
///       field must contain a single NUL character.
/// ```
#[allow(clippy::collapsible_if)]
pub(crate) fn validate_proxy_url(spec: &Url) -> Result<(), Error> {
    const SCHEMES: [&str; 3] = ["socks5", "socks4a", "http"];
    if !SCHEMES.contains(&spec.scheme()) {
        return Err(to_io_other(format!(
            "proxy URI has invalid scheme: {}",
            spec.scheme()
        )));
    }

    // when spec = http the path defaults to "/" instead of empty -_-
    if !spec.path().is_empty() {
        if !(spec.scheme() == "http" && spec.path() == "/") {
            return Err(to_io_other("proxy URI has a path defined "));
        }
    }
    if spec.query().is_some_and(|s| !s.is_empty()) {
        return Err(to_io_other("proxy URI has a query defined"));
    }
    if spec.fragment().is_some_and(|s| !s.is_empty()) {
        return Err(to_io_other("proxy URI has a fragment defined"));
    }
    if spec.port().is_none() {
        return Err(to_io_other("proxy URI lacks a port"));
    }

    match spec.scheme() {
        "socks5" => {
            let username = spec.username();
            let passwd = spec.password();

            // if either password or username is specified, then both must be non-empty
            if !username.is_empty() || passwd.is_some() {
                if username.is_empty() || username.len() > 255 {
                    return Err(to_io_other("proxy URI specified a invalid SOCKS5 username"));
                }
                if passwd.is_none() || passwd.is_some_and(|p| p.is_empty() || p.len() > 255) {
                    return Err(to_io_other("proxy URI specified a invalid SOCKS5 password"));
                }
            }
        }
        "socks4a" => {
            if spec.password().is_some() {
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

    if spec.host_str().is_none() {
        return Err(to_io_other("proxy URI has missing host"));
    }

    // not sure how better to combine host port.
    let mut sockaddr_string = String::from(spec.host_str().unwrap());
    sockaddr_string.push(':');
    sockaddr_string.push_str(&format!("{}", spec.port().unwrap()));
    let _ = resolve_addr(&sockaddr_string)
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
        let _ver = get_managed_transport_ver()?;
        debug!("VERSION {_ver}");

        let bind_addrs = Bindaddr::get_server_bindaddrs()?;

        let or_addr = match env::var(constants::ORPORT) {
            Ok(or_add_env) => Some(
                resolve_addr(or_add_env)
                    .map_err(|e| to_io_other(format!("cannot resolve TOR_PT_ORPORT: {e}")))?,
            ),
            Err(_) => None, // TOR_PT_ORPORT was not defined
        };

        let auth_cookie_path = env::var(constants::AUTH_COOKIE_FILE).ok();

        let extended_or_addr = match env::var(constants::EXTENDED_SERVER_PORT) {
            Ok(ext_or_addr_env) => Some(resolve_addr(ext_or_addr_env).map_err(|e| {
                to_io_other(format!("cannot resolve TOR_PT_EXTENDED_SERVER_PORT: {e}"))
            })?),
            Err(_) => None, // TOR_PT_EXTENDED_SERVER_PORT was not defined
        };

        if extended_or_addr.is_some() && auth_cookie_path.is_none() {
            return Err(to_io_other("need TOR_PT_AUTH_COOKIE_FILE environment variable with TOR_PT_EXTENDED_SERVER_PORT"));
        }

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
    pub fn new(method: &str, addr: SocketAddr, options: Args) -> Self {
        Self {
            method_name: method.into(),
            addr,
            options,
        }
    }

    /// Return an array of Bindaddrs, being the contents of TOR_PT_SERVER_BINDADDR
    /// with keys filtered by TOR_PT_SERVER_TRANSPORTS. Transport-specific options
    /// from TOR_PT_SERVER_TRANSPORT_OPTIONS are assigned to the Options member.
    pub(crate) fn get_server_bindaddrs() -> Result<Vec<Self>, Error> {
        // parse the list of server transport options
        let server_transport_opts =
            env::var(constants::SERVER_TRANSPORT_OPTIONS).unwrap_or_default();

        let mut options_map = Opts::parse_server_transport_options(&server_transport_opts)
            .map_err(|e| {
                to_io_other(format!(
                    "TOR_PT_SERVER_TRANSPORT_OPTIONS: {server_transport_opts}: \"{e}\""
                ))
            })?;

        // get the list of all requested bindaddrs
        let server_bindaddr = env::var(constants::SERVER_BINDADDR).map_err(to_io_other)?;
        if server_bindaddr.is_empty() {
            return Err(to_io_other(format!(
                "no \"{}\" environment variable value",
                constants::SERVER_BINDADDR
            )));
        }

        let mut results = Vec::new();
        let mut seen_methods = Vec::new();
        for spec in server_bindaddr.split(',') {
            let parts = spec.split_once('-');
            if parts.is_none() {
                return Err(to_io_other(format!(
                    "TPR_PT_SERVER_BINDADDR: {spec} doesn't contain \"-\""
                )));
            }
            let (method_name, addr) = parts.unwrap();

            // Check for duplicate method names: "Application MUST NOT set more
            // than one <address>:<port> pair per PT name."
            if seen_methods.contains(&method_name) {
                return Err(to_io_other(format!(
                    "TPR_PT_SERVER_BINDADDR: {spec} duplicate method name {method_name}"
                )));
            }
            seen_methods.push(method_name);
            let address = resolve_addr(addr)
                .map_err(|e| to_io_other(format!("TOR_PT_SERVER_BINDADDR: {spec}: {e}")))?;

            results.push(Bindaddr::new(
                method_name,
                address,
                options_map.remove(method_name).unwrap_or_default(),
            ));
        }
        let server_transports = env::var(constants::SERVER_TRANSPORTS).map_err(to_io_other)?;
        if server_transports.is_empty() {
            return Err(to_io_other(format!(
                "no \"{}\" environment variable value",
                constants::SERVER_TRANSPORTS
            )));
        }

        let result = filter_bindaddrs(results, &server_transports.split(',').collect_vec());
        Ok(result)
    }
}

fn filter_bindaddrs(addrs: Vec<Bindaddr>, methods: &[&str]) -> Vec<Bindaddr> {
    if methods.is_empty() {
        return Vec::new();
    }
    addrs
        .into_iter()
        .filter(|b| methods.contains(&b.method_name.as_str()))
        .collect()
}

pub fn resolve_addr(addr: impl AsRef<str>) -> Result<SocketAddr, Error> {
    let a = addr.as_ref();
    match SocketAddr::from_str(a) {
        Ok(sock_addr) => {
            if sock_addr.ip().is_unspecified() {
                return Err(to_io_other(format!("address string {a} lacks a host")));
            }

            if sock_addr.port() == 0 {
                return Err(to_io_other(format!("address string {a} lacks a port")));
            }
            Ok(sock_addr)
        }
        Err(e) => Err(to_io_other(format!("\"{a}\" - {e}"))),
    }
}

fn to_io_other(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Other, format!("{e}"))
}

#[cfg(test)]
#[serial_test::serial]
mod test {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn is_client_from_env() -> Result<(), Error> {
        env::remove_var(constants::CLIENT_TRANSPORTS);
        env::remove_var(constants::SERVER_TRANSPORTS);
        assert!(is_client().is_err());

        env::set_var(constants::CLIENT_TRANSPORTS, "trebuchet");
        env::remove_var(constants::SERVER_TRANSPORTS);
        assert!(is_client().is_ok_and(|is_client| is_client));

        env::remove_var(constants::CLIENT_TRANSPORTS);
        env::set_var(constants::SERVER_TRANSPORTS, "trebuchet1");
        assert!(is_client().is_ok_and(|is_client| !is_client));

        env::set_var(constants::CLIENT_TRANSPORTS, "trebuchet2");
        env::set_var(constants::SERVER_TRANSPORTS, "trebuchet2");
        assert!(is_client().is_err());

        Ok(())
    }

    #[test]
    fn statedir() -> Result<(), Error> {
        // TOR_PT_STATE_LOCATION not set.
        env::remove_var(constants::STATE_LOCATION);
        if make_state_dir().is_ok() {
            panic!("empty environment unexpectedly succeeded");
        }

        // Setup the scratch directory.
        let temp_dir = tempfile::tempdir()?;
        // temp_dir, err := ioutil.TempDir("", "testmake_state_dir")
        // if err != nil {
        //     t.Fatalf("ioutil.TempDir failed: %s", err)
        // }
        // defer os.RemoveAll(temp_dir)

        let good = vec![
            // Already existing directory.
            temp_dir.path().to_path_buf(),
            // Nonexistent directory, parent exists.
            temp_dir.path().join("parentExists"),
            // Nonexistent directory, parent doesn't exist.
            temp_dir.path().join("missingParent").join("parentMissing"),
        ];
        for trial in good {
            env::set_var("TOR_PT_STATE_LOCATION", trial.to_str().unwrap());
            let dir = make_state_dir()?;
            if dir != trial.to_str().unwrap() {
                panic!("make_state_dir returned an unexpected path {dir} (expecting {trial:?})");
            }
        }

        // Name already exists, but is an ordinary file.
        let temp_file = temp_dir.path().join("file");
        let _ = std::fs::File::create(&temp_file)?;

        env::set_var("TOR_PT_STATE_LOCATION", &temp_file);
        assert!(
            make_state_dir().is_err(),
            "make_state_dir with a file unexpectedly succeeded"
        );

        // Directory name that cannot be created. (Subdir of a file)
        env::set_var("TOR_PT_STATE_LOCATION", temp_file.join("subDir"));
        assert!(
            make_state_dir().is_err(),
            "make_state_dir with a subdirectory of a file unexpectedly succeeded"
        );

        Ok(())
    }

    #[test]
    fn server_bindaddrs() -> Result<(), Error> {
        // // test with env vars unset
        // assert_eq!(Bindaddr::get_server_bindaddrs().unwrap_err(), env::VarError);
        assert!(Bindaddr::get_server_bindaddrs().is_err());

        let bad = vec![
            // bad TOR_PT_SERVER_BINDADDR
            ("alpha", "alpha", ""),
            ("alpha-1.2.3.4", "alpha", ""),
            // missing TOR_PT_SERVER_TRANSPORTS
            ("alpha-1.2.3.4:1111", "", "alpha:key=value"),
            // bad TOR_PT_SERVER_TRANSPORT_OPTIONS
            ("alpha-1.2.3.4:1111", "alpha", "key=value"),
            // no escaping is defined for TOR_PT_SERVER_TRANSPORTS or
            // TOR_PT_SERVER_BINDADDR.
            (r"alpha\,beta-1.2.3.4:1111", r"alpha\,beta", ""),
            // duplicates in TOR_PT_SERVER_BINDADDR
            // https://bugs.torproject.org/21261
            (r"alpha-0.0.0.0:1234,alpha-[::]:1234", r"alpha", ""),
            (r"alpha-0.0.0.0:1234,alpha-0.0.0.0:1234", r"alpha", ""),
        ];

        for trial in bad {
            env::set_var(constants::SERVER_BINDADDR, trial.0);
            env::set_var(constants::SERVER_TRANSPORTS, trial.1);
            env::set_var(constants::SERVER_TRANSPORT_OPTIONS, trial.2);
            assert!(
                Bindaddr::get_server_bindaddrs().is_err(),
                "{:?} unexpectedly succeeded",
                trial
            );
        }

        let good = vec![
            (
                "alpha-1.2.3.4:1111,beta-[1:2::3:4]:2222",
                "alpha,beta,gamma",
                "alpha:k1=v1;beta:k2=v2;gamma:k3=v3",
                vec![
                    Bindaddr::new(
                        "alpha",
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1111),
                        args! {"k1"=>["v1"]},
                    ),
                    Bindaddr::new(
                        "beta",
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(1, 2, 0, 0, 0, 0, 3, 4)), 2222),
                        args! {"k2"=>["v2"]},
                    ),
                ],
            ),
            ("alpha-1.2.3.4:1111", "xxx", "", vec![]),
            (
                "alpha-1.2.3.4:1111",
                "alpha,beta,gamma",
                "",
                vec![Bindaddr::new(
                    "alpha",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1111),
                    Args::default(),
                )],
            ),
            (
                "trebuchet-127.0.0.1:1984,ballista-127.0.0.1:4891",
                "trebuchet,ballista",
                "trebuchet:secret=nou;trebuchet:cache=/tmp/cache;ballista:secret=yes",
                vec![
                    Bindaddr::new(
                        "trebuchet",
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1984),
                        args! {"secret"=>["nou"], "cache"=>["/tmp/cache"]},
                    ),
                    Bindaddr::new(
                        "ballista",
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4891),
                        args!("secret"=>["yes"]),
                    ),
                ],
            ),
            // In the past, "*" meant to return all known transport names.
            // But now it has no special meaning.
            // https://bugs.torproject.org/15612
            ("alpha-1.2.3.4:1111,beta-[1:2::3:4]:2222", "*", "", vec![]),
        ];

        for trial in good {
            env::set_var(constants::SERVER_BINDADDR, trial.0);
            env::set_var(constants::SERVER_TRANSPORTS, trial.1);
            env::set_var(constants::SERVER_TRANSPORT_OPTIONS, trial.2);

            let out = Bindaddr::get_server_bindaddrs();
            assert!(out.is_ok(), "{:?} unexpectedly failed: {out:?}", trial);

            assert_eq!(out.unwrap(), trial.3);
        }
        Ok(())
    }

    #[test]
    fn validate_url() -> Result<(), Error> {
        env::remove_var(constants::PROXY);
        assert!(get_proxy_url().is_ok_and(|url| url.is_none()));

        let bad_url = vec![
            "asdals;kdmma",
            "http/example.com",
            "127.0.0.1:8080",
            "socks5://admin:admin@:9000", // No host
        ];

        let bad = vec![
            "socks5://admin:admin@1.2.3.4:",
            "ftp://127.0.0.1:8000",              // invalid protocol
            "socks5://aaa:bbb@1.2.3.4:80/a/b/c", // includes path
            "socks5://aaa:bbb@1.2.3.4:80/?labels=E-easy&state=open", // includes query
            "socks5://aaa:bbb@1.2.3.4:80#row=4", // includes fragment
            "socks5://myhost",                   // no username / password
            "socks5://myproxy:8080",             // uses non-IP host alias
            "socks5://aaa:bbb@myhost.com:8888",  // uses domain name
            "socks5://aaa:bbb@myhost",           // uses non-IP host alias
            "socks4a://:admin@1.2.3.4:8080",     // no username, but password defined
            "http://admin:admin@example.com",
            "socks5://1.2.3.4", // no port
            "socks5://[1:2::3:4]",
            "socks5://admin:admin@1.2.3.4",
            "socks4a://1.2.3.4",
            "socks4a://[1:2::3:4]",
            "socks5://admin:admin@[1:2::3:4]",
            "socks4a://admin:admin@1.2.3.4:8080", // socks4 with password
            "socks4a://:admin@1.2.3.4:8080",      // socks4a with password
            "socks5://admin@[1:2::3:4]:9000",     // socks5 with username, but no password
            "socks5://:admin@[1:2::3:4]:9000",    // socks5 wuth password, but no username
        ];

        let good = vec![
            "socks5://127.0.0.1:8080",
            "socks5://1.2.3.4:8080",
            "socks5://[1:2::3:4]:8080",
            "socks5://admin:admin@1.2.3.4:8080",
            "socks5://admin:admin@1.2.3.4:8080",
            "socks5://admin:admin@[1:2::3:4]:9000",
            "socks4a://1.2.3.4:8080",
            "socks4a://[1:2::3:4]:8080",
            "socks4a://admin@1.2.3.4:8080",
            "http://1.2.3.4:8080",
            "http://[1:2::3:4]:8080",
            "http://admin@1.2.3.4:8080",
            "http://admin:admin@1.2.3.4:8080",
        ];

        for trial in bad_url {
            let url = Url::parse(trial);
            assert!(
                url.is_err(),
                "\"{trial}\" unexpectedly succeeded in parsing: {url:?}"
            );
        }

        for trial in bad {
            let url = Url::parse(trial).unwrap();
            assert!(
                validate_proxy_url(&url).is_err(),
                "\"{trial}\" unexpectedly succeeded validation: {url:?}"
            );
        }

        for trial in good {
            env::set_var(constants::PROXY, trial);

            let res = get_proxy_url();
            assert!(
                res.is_ok(),
                "\"{trial}\" unexpectedly failed to validate: {res:?}"
            );
        }

        Ok(())
    }

    #[test]
    fn client_transports() -> Result<(), Error> {
        let tests: Vec<(&str, Vec<&str>)> = vec![
            ("alpha", vec!["alpha"]),
            ("alpha,beta", vec!["alpha", "beta"]),
            ("alpha,beta,gamma", vec!["alpha", "beta", "gamma"]),
            // In the past, "*" meant to return all known transport names.
            // But now it has no special meaning.
            // https://bugs.torproject.org/15612
            ("*", vec!["*"]),
            ("alpha,*,gamma", vec!["alpha", "*", "gamma"]),
            // No escaping is defined for TOR_PT_CLIENT_TRANSPORTS.
            ("alpha\\,beta", vec!["alpha\\", "beta"]),
        ];

        for trial in tests {
            env::set_var(constants::CLIENT_TRANSPORTS, trial.0);
            let result = get_client_transports()?;
            assert_eq!(result, trial.1);
        }

        Ok(())
    }

    #[test]
    fn resolve() -> Result<(), Error> {
        let bad = vec![
            "",
            "1.2.3.4",
            "1.2.3.4:",
            "9999",
            ":9999",
            "[1:2::3:4]",
            "[1:2::3:4]:",
            "[1::2::3:4]",
            "1:2::3:4::9999",
            "1:2::3:4:9999", // moved from good cases since this is not proper format
            "1:2:3:4::9999",
            "localhost:9999",
            "[localhost]:9999",
            "1.2.3.4:http",
            "1.2.3.4:0x50",
            "1.2.3.4:-65456",
            "1.2.3.4:65536",
            "1.2.3.4:80\x00",
            "1.2.3.4:80 ",
            " 1.2.3.4:80",
            "1.2.3.4 : 80",
            "www.google.com", // not a socket address (domain)
            "google.com:443", // not a socket address (domain)
            "0.0.0.0:9000",   // no address specified
            "[0::0000]:9000", // no address specified
            "127.0.0.1:0",    // no port specified
            "[1234::cdef]:0", // no port specified
            "127.0.0",        // not an address
        ];
        let good: Vec<(&str, SocketAddr)> = vec![
            (
                "1.2.3.4:9999",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 9999),
            ),
            (
                "[1:2::3:4]:9999",
                SocketAddr::new(IpAddr::V6(Ipv6Addr::new(1, 2, 0, 0, 0, 0, 3, 4)), 9999),
            ),
            // // this is not a properly formatted ipv6 address
            // ("1:2::3:4:9999",SocketAddr::new(IpAddr::V6(Ipv6Addr::new(1, 2, 0, 0, 0, 0, 3, 4)), 9999)),
        ];

        for trial in good {
            let res = resolve_addr(trial.0).unwrap();
            assert_eq!(res, trial.1);
        }

        for trial in bad {
            assert!(resolve_addr(trial).is_err());
        }
        Ok(())
    }

    #[test]
    fn managed_ver() -> Result<(), Error> {
        let good = vec!["1", "1,1", "1,2", "2,1", "3,2,1", "3,1,2"];

        for trial in good {
            env::set_var(constants::MANAGED_VER, trial);
            assert_eq!(
                get_managed_transport_ver()?,
                constants::CURRENT_TRANSPORT_VER
            );
        }

        env::set_var(constants::MANAGED_VER, "");
        assert!(get_managed_transport_ver().is_err());

        env::set_var(constants::MANAGED_VER, "3,2");
        assert!(get_managed_transport_ver().is_err());

        Ok(())
    }
}
