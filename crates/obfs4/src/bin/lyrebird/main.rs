//! Lyrebird client
//!
//! TODO: (priority: after mvp)
//!   - use tunnel_manager for managing proxy connections so we can track metrics
//!     about tunnel failures and bytes transferred.
//!   - find a way to apply a rate limit to copy bidirectional
//!   - use the better copy interactive for bidirectional copy
#![allow(unused,dead_code)]

use ptrs::{ClientTransport, PluggableTransport};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use fast_socks5::server::AcceptAuthentication;
use fast_socks5::util::target_addr::TargetAddr;
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal::unix::SignalKind,
    sync::oneshot,
};
// use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
// use tor_chanmgr::transport::proxied::{settings_to_protocol, Protocol};
// use tor_linkspec::PtTransportName;
// use tor_ptmgr::ipc::{
//     PtClientParameters,
//     PtCommonParameters,
//     PtServerParameters,
//     // PluggableClientTransport, PluggableServerTransport, // PluggableTransport
// };
// use tor_rtcompat::PreferredRuntime;
// use tor_socksproto::{SocksAuth, SocksVersion};
use tracing::{error, info, warn, Level};
use tracing_subscriber::{filter::LevelFilter, prelude::*};

use std::net::SocketAddr;
use std::{env, fs::DirBuilder, os::unix::fs::DirBuilderExt, str::FromStr, sync::Arc};

// /// The location where the obfs4 server will store its state
// const SERVER_STATE_LOCATION: &str = "/tmp/arti-pt";
// /// The location where the obfs4 client will store its state
// const CLIENT_STATE_LOCATION: &str = "/tmp/arti-pt-client";

/// Error defined to denote a failure to get the bridge line
#[derive(Debug, thiserror::Error)]
#[error("Error while obtaining bridge line data")]
struct BridgeLineParseError;

/// Tunnel SOCKS5 traffic through obfs4 connections
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Log to {TOR_PT_STATE_LOCATION}/obfs4proxy.log
    #[arg(long, default_value_t = false)]
    enable_logging: bool,

    /// Log Level (ERROR/WARN/INFO/DEBUG/TRACE)
    #[arg(long, default_value_t=String::from("ERROR"))]
    log_level: String,

    /// Disable the address scrubber on logging
    #[arg(long, default_value_t = false)]
    unsafe_logging: bool,
}

fn is_client() -> Result<bool> {
    let is_client = env::var_os("TOR_PT_CLIENT_TRANSPORTS");
    let is_server = env::var_os("TOR_PT_SERVER_TRANSPORTS");

    match (is_client, is_server) {
        (Some(_), Some(_)) => Err(anyhow!(
            "ENV-ERROR TOR_PT_[CLIENT,SERVER]_TRANSPORTS both set"
        )),
        (Some(_), None) => Ok(true),
        (None, Some(_)) => Ok(false),
        (None, None) => Err(anyhow!("not launched as a managed transport")),
    }
}

fn make_state_dir() -> Result<String> {
    let path = env::var("TOR_PT_STATE_LOCATION")
        .context("missing required TOR_PT_STATE_LOCATION env var")?;

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&path)?;
    Ok(path)
}

/// initialize the logging receiver(s) for things to be logged into using the
/// tracing / tracing_subscriber libraries
// TODO: unsafe / should scrub to remove addresses. GeoIP. Json for file log writer.
fn init_logging_recvr(
    enable: bool,
    _should_scrub: bool,
    level_str: &str,
    statedir: &str,
) -> Result<()> {
    // let filter_unsafe = FilterFn::new(|mut md|{

    //     if md.fields().contains(Field::new("client_addr")) {
    //         md.field("client_addr");
    //     }

    //     true
    // });

    let console_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_writer(std::io::stdout)
        .with_filter(LevelFilter::INFO);

    let log_layers = if enable {
        let level = Level::from_str(level_str)?;

        let file = std::fs::File::create(format!("{statedir}/obfs4proxy.log"))?;

        let state_dir_layer = tracing_subscriber::fmt::layer()
            .with_writer(file)
            .with_filter(LevelFilter::from_level(level));

        console_layer.and_then(state_dir_layer).boxed()
    } else {
        console_layer.boxed()
    };

    tracing_subscriber::registry().with(log_layers).init();

    Ok(())
}

// ================================================================ //
//                            Client                                //
// ================================================================ //

async fn client_setup(
    statedir: &str,
    cancel_token: CancellationToken,
) -> Result<oneshot::Receiver<bool>> {
    let client_pt_info = ptrs::ClientInfo::new()?;
    let proxy_uri = client_pt_info.uri.ok_or(BridgeLineParseError)?;
    let (tx, rx) = oneshot::channel::<bool>();

    // // This only launches lyrebird / obfs4 for now and doesn't track other PT types
    // for name in client_pt_info.methods {
    //     info!(name);

    //     let builder = match ptrs::try_get_transport(name) {
    //         Ok(b) => b,
    //         Err(e) => {
    //             warn!("unrecognized transport {name}");
    //             continue
    //         }
    //     };
    if !client_pt_info
        .methods
        .contains(&obfs4::Transport::NAME.to_string())
    {
        error!("cannot launch unrecognized pluggable transports")
    }

    let builder =
        <obfs4::Transport as ptrs::PluggableTransport<TcpStream>>::ClientBuilder::default();
    let pt_name = <obfs4::Transport as PluggableTransport<TcpStream>>::name();
    let listener = tokio::net::TcpListener::bind(":8080").await?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => info!("{pt_name} received shutdown signal"),
                res = listener.accept() => {
                    let (conn, client_addr) = match res {
                        Err(e) => {
                            error!("failed to accept tcp connection {e}");
                            break;
                        }
                        Ok(c) => c,
                    };
                    tokio::spawn(client_handle_connection_builder(
                        conn,
                        builder.clone(),
                        proxy_uri.clone(),
                        elide_addr(client_addr),
                    ));
                }
            }
        }

        tx.send(true).unwrap()
    });
    // }

    Ok(rx)
}

/// This function assumes that the provided connection / socket manages reconstruction
/// and reliability before passing to this layer.
async fn client_handle_connection_builder<In, B>(
    conn: In,
    builder: B,
    _proxy_uri: url::Url,
    client_addr: impl AsRef<str> + tracing::Value,
) -> Result<()>
where
    // the provided T must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Unpin,
    // the provided B must implement the Client Builder interface for T
    B: ptrs::ClientBuilderByTypeInst<TcpStream>, // , Error = std::io::Error>,

    <B as ptrs::ClientBuilderByTypeInst<TcpStream>>::ClientPT:
        ptrs::ClientTransport<TcpStream, std::io::Error>,

    <<B as ptrs::ClientBuilderByTypeInst<TcpStream>>::ClientPT as ClientTransport<
        TcpStream,
        std::io::Error,
    >>::OutRW: AsyncRead + AsyncWrite + Send + Unpin,

    <<B as ptrs::ClientBuilderByTypeInst<TcpStream>>::ClientPT as ClientTransport<
        TcpStream,
        std::io::Error,
    >>::OutErr: Send + Sync + Unpin + 'static,

    // When the client transport built by B is used to wrap T the resulting
    // object must also function as a connection in an async context.
    <<B as ptrs::ClientBuilderByTypeInst<TcpStream>>::ClientPT as ptrs::ClientTransport<
        TcpStream,
        <B as ptrs::ClientBuilderByTypeInst<TcpStream>>::Error,
    >>::OutRW: AsyncRead + AsyncWrite + Send + Unpin,

    // When the client transport built by B is used to wrap T but fails, the
    // resulting error must be a valid standard error.
    <<B as ptrs::ClientBuilderByTypeInst<TcpStream>>::ClientPT as ptrs::ClientTransport<
        TcpStream,
        <B as ptrs::ClientBuilderByTypeInst<TcpStream>>::Error,
    >>::OutErr: Send + Sync + 'static,
{
    let mut config: fast_socks5::server::Config<AcceptAuthentication> =
        fast_socks5::server::Config::default();
    config.set_skip_auth(true);
    let socks5_conn = fast_socks5::server::Socks5Socket::new(conn, Arc::new(config));

    let socks5_conn = socks5_conn.upgrade_to_socks5().await?;
    let target_addr = socks5_conn
        .target_addr()
        .ok_or(BridgeLineParseError)
        .context("missing remote address in request")?;
    // TODO: get args from the socks request
    // let args = socks5_conn.get_args();

    // // I am not sure we even enable socks auth for the local client proxy
    // if socks5_conn.auth() != AuthenticationMethod::Password { username: (), password: () } {
    //     warn!(address=client_addr, "failed to authenticate client socks5 conn");
    //     return
    // }

    let remote_addr = resolve_target_addr(target_addr)?
        .ok_or(BridgeLineParseError)
        .context("no remote address")?;

    let remote = tokio::net::TcpStream::connect(remote_addr);

    // build the pluggable transport client and then dial, completing the
    // connection and handshake when the `wrap(..)` is await-ed.
    let pt_client = builder.build();
    let mut pt_conn = match ptrs::ClientTransport::<TcpStream, std::io::Error>::establish(
        pt_client,
        Box::pin(remote),
    )
    .await
    {
        Err(e) => {
            warn!(address = client_addr, "handshake failed: {e:#?}");
            return Err(obfs4::Error::Other(Box::new(e))).context("handshake failed");
        }
        Ok(c) => c,
    };

    if let Err(e) = copy_bidirectional(&mut socks5_conn.into_inner(), &mut pt_conn).await {
        warn!(addres = client_addr, "tunnel closed with error: {e:#?}");
    }
    Ok(())
}

fn resolve_target_addr(addr: &TargetAddr) -> Result<Option<SocketAddr>> {
    match addr {
        TargetAddr::Ip(sa) => Ok(Some(sa.clone())),
        TargetAddr::Domain(_, _) => {
            ptrs::resolve_addr(Some(format!("{addr}"))).context("domain resolution failed")
        }
    }
}

// ================================================================ //
//                            Server                                //
// ================================================================ //

async fn server_setup(
    _statedir: &str,
    _cancel_token: CancellationToken,
) -> Result<oneshot::Receiver<bool>> {
    let _server_info = ptrs::ServerInfo::new()?;
    let (_tx, rx) = oneshot::channel::<bool>();

    Ok(rx)
}

async fn server_handle_connection() -> Result<()> {
    Ok(())
}

/// Main function, ties everything together and parses arguments etc.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Make state directory
    let statedir = make_state_dir()?;

    // launch tracing subscriber with filter level
    init_logging_recvr(
        args.enable_logging,
        !args.unsafe_logging,
        &args.log_level,
        &statedir,
    )?;

    let cancel_token = tokio_util::sync::CancellationToken::new();

    // launch runners
    let mut exit_rx = if is_client()? {
        // running as CLIENT
        client_setup(&statedir, cancel_token.clone()).await?
    } else {
        // running as SERVER
        server_setup(&statedir, cancel_token.clone()).await?
    };

    info!("accepting connections");

    // At this point, the pt config protocol is finished, and incoming
    // connections will be processed.  Wait till the parent dies
    // (immediate exit), a SIGTERM is received (immediate exit),
    // or a SIGINT is received.
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
    tokio::select! {
        _ = &mut exit_rx => {
            info!("proxy closed");
            return Ok(())
        }
        _ = sigterm.recv() => {
            info!("proxy terminated");
            return Ok(())
        }
        _ = sigint.recv()=> {
            info!("received iterrupt, shutting down");
            cancel_token.cancel();
        }
    }

    // Ok, it was the first SIGINT, close all listeners, and wait till,
    // the parent dies, all the current connections are closed, or either
    // a SIGINT/SIGTERM is received, and exit.
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
    tokio::select! {
        _ = exit_rx => {}
        _ = sigint.recv()=> {}
        _ = sigterm.recv() => {}
    }

    Ok(())
}

/// Store the data we need to connect to the obfs4 client
///
/// The obfs4 client in turn connects to the obfs4 server
#[derive(Clone)]
struct ForwardingCreds {
    username: String,
    password: String,
    forward_endpoint: String,
    obfs4_server_ip: String,
    obfs4_server_port: u16,
}

fn elide_addr(s: std::net::SocketAddr) -> String {
    // TODO: actually elide addres based on settings
    s.to_string()
}

// /// Create the config to launch an obfs4 server process
// fn build_server_config(
//     protocol: &str,
//     bind_addr: &str,
//     forwarding_server_addr: &str,
// ) -> Result<(PtCommonParameters, PtServerParameters)> {
//     let bindaddr_formatted = format!("{}-{}", &protocol, bind_addr);
//     let orport = forwarding_server_addr.to_string();
//     Ok((
//         PtCommonParameters::builder()
//             .state_location(SERVER_STATE_LOCATION.into())
//             .timeout(Some(Duration::from_secs(1)))
//             .build()?,
//         PtServerParameters::builder()
//             .transports(vec![protocol.parse()?])
//             .server_bindaddr(bindaddr_formatted)
//             .server_orport(Some(orport))
//             .build()?,
//     ))
// }

// /// Read cert info and relay it to the user
// fn read_cert_info() -> Result<String> {
//     let file_path = format!("{}/obfs4_bridgeline.txt", SERVER_STATE_LOCATION);
//     match std::fs::read_to_string(file_path) {
//         Ok(contents) => {
//             let line = contents
//                 .lines()
//                 .find(|line| line.contains("Bridge obfs4"))
//                 .ok_or(BridgeLineParseError)?;
//             let cert = line
//                 .split_whitespace()
//                 .find(|part| part.starts_with("cert="))
//                 .ok_or(BridgeLineParseError)?;
//             let iat = line
//                 .split_whitespace()
//                 .find(|part| part.starts_with("iat-mode="))
//                 .ok_or(BridgeLineParseError)?;
//             let complete_config = format!("{};{}", cert, iat);
//             Ok(complete_config)
//         }
//         Err(e) => Err(e.into()),
//     }
// }

// /// Create the config to launch an obfs4 client process
// fn build_client_config(protocol: &str) -> Result<(PtCommonParameters, PtClientParameters)> {
//     Ok((
//         PtCommonParameters::builder()
//             .state_location(CLIENT_STATE_LOCATION.into())
//             .timeout(Some(Duration::from_secs(1)))
//             .build()?,
//         PtClientParameters::builder()
//             .transports(vec![protocol.parse()?])
//             .build()?,
//     ))
// }
//
// /// Create a SOCKS5 connection to the obfs4 client
// async fn connect_to_obfs4_client(
//     forward_creds: ForwardingCreds,
// ) -> Result<Socks5Stream<TcpStream>> {
//     let config = Config::default();
//     Ok(Socks5Stream::connect_with_password(
//         forward_creds.forward_endpoint,
//         forward_creds.obfs4_server_ip,
//         forward_creds.obfs4_server_port,
//         forward_creds.username,
//         forward_creds.password,
//         config,
//     )
//     .await?)
// }
//
// /// Launch the dumb TCP pipe, whose only job is to abstract away the obfs4 client
// /// and its complicated setup, and just forward bytes between the obfs4 client
// /// and the client
// async fn run_forwarding_server(endpoint: &str, forward_creds: ForwardingCreds) -> Result<()> {
//     let listener = TcpListener::bind(endpoint).await?;
//     while let Ok((mut client, _)) = listener.accept().await {
//         let forward_creds_clone = forward_creds.clone();
//         match connect_to_obfs4_client(forward_creds_clone).await {
//             Ok(mut relay_stream) => {
//                 if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut relay_stream).await
//                 {
//                     eprintln!("{:#?}", e);
//                 }
//             }
//             Err(e) => {
//                 eprintln!("Couldn't connect to obfs4 client: \"{}\"", e);
//                 // Report "No authentication method was acceptable" to user
//                 // For more info refer to RFC 1928
//                 client.write_all(&[5, 0xFF]).await.unwrap();
//             }
//         }
//     }
//     Ok(())
// }
//
// /// Run the final hop of the connection, which finally makes the actual
// /// network request to the intended host and relays it back
// async fn run_socks5_server(endpoint: &str) -> Result<oneshot::Receiver<bool>> {
//     let listener = Socks5Server::<AcceptAuthentication>::bind(endpoint).await?;
//     let (tx, rx) = oneshot::channel::<bool>();
//     tokio::spawn(async move {
//         while let Some(Ok(socks_socket)) = listener.incoming().next().await {
//             tokio::spawn(async move {
//                 if let Err(e) = socks_socket.upgrade_to_socks5().await {
//                     eprintln!("{:#?}", e);
//                 }
//             });
//         }
//         tx.send(true).unwrap()
//     });
//     Ok(rx)
// }

// for _, ln := range ptListeners {
// >   ln.Close()
// }

// match args.command {
//     Command::Client {
//         client_port,
//         remote_obfs4_ip,
//         remote_obfs4_port,
//         obfs4_auth_info: obfs4_server_conf,
//     } => {
//         let entry_addr = format!("127.0.0.1:{}", client_port);

//         let client_pt = launch_obfs4_client_process(obfs4_path).await?;
//         let client_endpoint = client_pt
//             .transport_methods()
//             .get(&PtTransportName::from_str("obfs4")?)
//             .unwrap()
//             .endpoint()
//             .to_string();

//         let settings = settings_to_protocol(SocksVersion::V5, obfs4_server_conf)?;
//         match settings {
//             Protocol::Socks(_, auth) => match auth {
//                 SocksAuth::Username(raw_username, raw_password) => {
//                     let username = String::from_utf8(raw_username)?;
//                     let password = match raw_password.is_empty() {
//                         true => String::from("\0"),
//                         false => String::from_utf8(raw_password)?,
//                     };
//                     let creds = ForwardingCreds {
//                         username,
//                         password,
//                         forward_endpoint: client_endpoint,
//                         obfs4_server_ip: remote_obfs4_ip,
//                         obfs4_server_port: remote_obfs4_port,
//                     };
//                     info!("Listening on: {}", entry_addr);
//                     run_forwarding_server(&entry_addr, creds).await?;
//                 }
//                 _ => eprintln!("Unable to get credentials for obfs4 client process!"),
//             },
//             _ => eprintln!("Unexpected protocol"),
//         }
//     }
//     Command::Server {
//         listen_address,
//         final_socks5_port,
//     } => {
//         let final_socks5_endpoint = format!("127.0.0.1:{}", final_socks5_port);
//         let exit_rx = run_socks5_server(&final_socks5_endpoint).await?;
//         info!("Listening on: {}", listen_address);
//         launch_obfs4_server_process(obfs4_path, listen_address, final_socks5_endpoint).await?;
//         let auth_info = read_cert_info().unwrap();
//         info!("Authentication info is: {}", auth_info);
//         exit_rx.await.unwrap();
//     }
// }

/*
/// Launch obfs4 client process
async fn launch_obfs4_client_process(
    obfs4_path: String,
) -> Result<PluggableClientTransport> {
    let (common_params, client_params) = build_client_config("obfs4")?;

    info!("Launching pluggable transport obfs4");

    // let mut client_pt = PluggableClientTransport::new(
    //     obfs4_path.into(),
    //     vec![
    //         "-enableLogging".to_string(),
    //         "-logLevel".to_string(),
    //         "DEBUG".to_string(),
    //         "-unsafeLogging".to_string(),
    //     ],
    //     common_params,
    //     client_params,
    // );
    // client_pt.launch(PreferredRuntime::current()?).await?;

    Ok(client_pt)
}

/// Launch obfs4 server process
async fn launch_obfs4_server_process(
    obfs4_path: String,
    listen_address: String,
    final_socks5_endpoint: String,
) -> Result<PluggableServerTransport> {
    let (common_params, server_params) =
        build_server_config("obfs4", &listen_address, &final_socks5_endpoint)?;


    info!("Launching pluggable transport obfs4");

    // let mut server_pt = PluggableServerTransport::new(
    //     obfs4_path.into(),
    //     vec![
    //         "-enableLogging".to_string(),
    //         "-logLevel".to_string(),
    //         "DEBUG".to_string(),
    //         "-unsafeLogging".to_string(),
    //     ],
    //     common_params,
    //     server_params,
    // );
    // server_pt.launch(PreferredRuntime::current()?).await?;

    Ok(server_pt)
} */
