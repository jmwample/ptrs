use std::{
    borrow::Cow,
    collections::HashMap,
    env,
    io::{Error, ErrorKind},
    net::SocketAddr,
};

use tracing::{debug, warn};
use url::Url;

pub(crate) fn get_managed_transport_ver() -> Result<String, Error> {
    Ok("".into())
}

pub fn parse_smethod_args(
    args: impl AsRef<str>,
) -> Result<HashMap<String, String>, Cow<'static, str>> {
    let words = args.as_ref().split_whitespace();

    let mut parsed_args = HashMap::new();

    // NOTE(eta): pt-spec.txt seems to imply these options can't contain spaces, so
    //            we work under that assumption.
    //            It also doesn't actually parse them out -- but seeing as the API to
    //            feed these back in will want them as separated k/v pairs, I think
    //            it makes sense to here.
    for option in words {
        if let Some(mut args) = option.strip_prefix("ARGS:") {
            while !args.is_empty() {
                let (k, v, rest) = parse_one_smethod_arg(args)
                    .map_err(|e| Cow::from(format!("failed to parse SMETHOD ARGS: {}", e)))?;
                if parsed_args.contains_key(&k) {
                    // At least check our assumption that this is actually k/v
                    // and not Vec<(String, String)>.
                    warn!("PT SMETHOD arguments contain repeated key {}!", k);
                }
                parsed_args.insert(k, v);
                args = rest;
            }
        }
    }

    Ok(parsed_args)
}

/// Chomp one key/value pair off a list of smethod args.
/// Returns (k, v, unparsed rest of string).
/// Will also chomp the comma at the end, if there is one.
fn parse_one_smethod_arg(args: &str) -> Result<(String, String, &str), &'static str> {
    // NOTE(eta): Apologies for this looking a bit gnarly. Ideally, this is what you'd use
    //            something like `nom` for, but I didn't want to bring in a dep just for this.

    let mut key = String::new();
    let mut val = String::new();
    // If true, we're reading the value, not the key.
    let mut reading_val = false;
    let mut chars = args.chars();
    while let Some(c) = chars.next() {
        let target = if reading_val { &mut val } else { &mut key };
        match c {
            '\\' => {
                let c = chars
                    .next()
                    .ok_or("smethod arg terminates with backslash")?;
                target.push(c);
            }
            '=' => {
                if reading_val {
                    return Err("encountered = while parsing value");
                }
                reading_val = true;
            }
            ',' => break,
            c => target.push(c),
        }
    }
    if !reading_val {
        return Err("ran out of chars parsing smethod arg");
    }
    Ok((key, val, chars.as_str()))
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
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to parse proxy config: {e}"),
            ))
        }
    };

    // Url::parse() only works for absolute urls so we do not need to check for relative
    let uri = Url::parse(&url_str).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("failed to parse proxy config \"{url_str}\": {e}"),
        )
    })?;

    validate_proxy_url(&uri)?;

    Ok(Some(uri))
}

pub(crate) fn validate_proxy_url(spec: &Url) -> Result<(), Error> {
    if !spec.path().is_empty() {
        return Err(Error::new(ErrorKind::Other, "proxy URI has a path defined"));
    }
    if spec.query().is_some_and(|s| !s.is_empty()) {
        return Err(Error::new(
            ErrorKind::Other,
            "proxy URI has a query defined",
        ));
    }
    if spec.fragment().is_some_and(|s| !s.is_empty()) {
        return Err(Error::new(
            ErrorKind::Other,
            "proxy URI has a fragment defined",
        ));
    }

    match spec.scheme() {
        "socks5" => {
            let username = spec.username();
            let passwd = spec.password();

            if username.is_empty() || username.len() > 255 {
                return Err(Error::new(
                    ErrorKind::Other,
                    "proxy URI specified a invalid SOCKS5 username",
                ));
            }
            if passwd.is_none() || passwd.is_some_and(|p| p.is_empty() || p.len() > 255) {
                return Err(Error::new(
                    ErrorKind::Other,
                    "proxy URI specified a invalid SOCKS5 password",
                ));
            }
        }
        "socks4a" => {
            if !spec.username().is_empty() && spec.password().is_some_and(|p| !p.is_empty()) {
                return Err(Error::new(
                    ErrorKind::Other,
                    "proxy URI specified SOCKS4a and a password",
                ));
            }
        }
        "http" => {}
        _ => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("proxy URI has invalid scheme: {}", spec.scheme()),
            ))
        }
    }

    _ = resolve_addr(spec.host_str())
        .map_err(|e| Error::new(ErrorKind::Other, format!("proxy URI has invalid host: {e}")))?;

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
pub struct ServerInfo {
    pub bind_addrs: Vec<()>,
    pub or_addr: Option<SocketAddr>,
    pub extended_or_addr: Option<SocketAddr>,
    pub auth_cookie_path: Option<String>,
}

impl ServerInfo {
    pub fn new() -> Result<Self, Error> {
        let ver = get_managed_transport_ver()?;
        debug!("VERSION {ver}");

        let bind_addrs = get_server_bind_addrs()?;

        let or_add_env = env::var_os("TOR_PT_ORPORT").map(|s| s.into_string().unwrap());
        let or_addr = resolve_addr(or_add_env).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("cannot resolve TOR_PT_ORPORT: {e}"),
            )
        })?;

        let auth_cookie_path = env::var("TOR_PT_AUTH_COOKIE_FILE").ok();

        let ext_or_addr_env =
            env::var_os("TOR_PT_EXTENDED_SERVER_PORT").map(|s| s.into_string().unwrap());

        if ext_or_addr_env.clone().is_some_and(|s| !s.is_empty()) && auth_cookie_path.is_none() {
            return Err(Error::new(ErrorKind::Other, "need TOR_PT_AUTH_COOKIE_FILE environment variable with TOR_PT_EXTENDED_SERVER_PORT"));
        }

        let extended_or_addr = resolve_addr(ext_or_addr_env).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("cannot resolve TOR_PT_EXTENDED_SERVER_PORT: {e}"),
            )
        })?;

        // Need either OrAddr or ExtendedOrAddr.
        if or_addr.is_none() && extended_or_addr.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
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

pub(crate) fn get_server_bind_addrs() -> Result<Vec<()>, Error> {
    Ok(vec![])
}

pub fn resolve_addr(_addr: Option<impl AsRef<str>>) -> Result<Option<SocketAddr>, Error> {
    Ok(None)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn resolve() -> Result<(), Error> {
        resolve_addr(None::<String>).unwrap();

        Ok(())
    }
}
