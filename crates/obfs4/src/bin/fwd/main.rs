//! Lyrebird client
//!
//! TODO: (priority: after mvp)
//!   - use tunnel_manager for managing proxy connections so we can track metrics
//!     about tunnel failures and bytes transferred.
//!   - find a way to apply a rate limit to copy bidirectional
//!   - use the better copy interactive for bidirectional copy
#![allow(unused, dead_code)]

use obfs4::{obfs4::ClientBuilder, Obfs4PT};
use ptrs::{ClientTransport, PluggableTransport, ServerBuilder, ServerTransport};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use fast_socks5::{
    server::{DenyAuthentication, SimpleUserPassword},
    util::target_addr::TargetAddr,
    AuthenticationMethod,
};
use safelog::sensitive;
use tokio::task::JoinSet;
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal::unix::SignalKind,
    sync::oneshot,
};
use tokio_util::sync::CancellationToken;
// use tokio_stream::StreamExt;
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
use tracing::{error, info, debug, warn, Level};
use tracing_subscriber::{filter::LevelFilter, prelude::*};

use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

/// Client Socks address to listen on.
const CLIENT_SOCKS_ADDR: &str = "127.0.0.1:0";

/// Error defined to denote a failure to get the bridge line
#[derive(Debug, thiserror::Error)]
#[error("Error while obtaining bridge line data")]
struct BridgeLineParseError;

/// Tunnel SOCKS5 traffic through obfs4 connections
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run in server mode or client mode
    mode: Mode,

    /// Target address, server address when running as client, forward address when running as
    /// server
    dst: String,

    /// Listen address, defaults to ":9000" for client, ":9001" for server
    laddr: Option<String>,

    /// Log Level (ERROR/WARN/INFO/DEBUG/TRACE)
    #[arg(short, long, default_value_t=String::from("ERROR"))]
    log_level: String,

    /// Disable the address scrubber on logging
    #[arg(long, action)]
    unsafe_logging: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Mode {
    /// Run as client forward proxy
    Client,
    /// Run as server handling terminating pt connections and forwarding to socks proxy
    Server,
}

/// initialize the logging receiver(s) for things to be logged into using the
/// tracing / tracing_subscriber libraries
// TODO: GeoIP. Json for file log writer.
fn init_logging_recvr(unsafe_logging: bool, level_str: &str) -> Result<safelog::Guard> {

    let log_lvl = LevelFilter::from_str(level_str)?;

    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_filter(log_lvl);

    tracing_subscriber::registry()
        .with(console_layer.boxed())
        .init();
    warn!("log level set to {level_str}");

    if unsafe_logging {
        info!("⚠️ ⚠️  enabling unsafe logging ⚠️ ⚠️ ");
        safelog::disable_safe_logging().context("failed to get safelog Guard")
    } else {
        safelog::enforce_safe_logging().context("failed to get safelog Guard")
    }
}

/// Main function, ties everything together and parses arguments etc.
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("unsafe_logging: {}",args.unsafe_logging);
    // launch tracing subscriber with filter level
    let _guard = init_logging_recvr(args.unsafe_logging, &args.log_level)?;

    let dst_addr = SocketAddr::from_str(&args.dst)?;

    let listen_addr = match args.laddr {
        Some(a) => SocketAddr::from_str(&a)?,
        None => match args.mode {
            Mode::Client => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9000)),
            Mode::Server => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9001)),
        },
    };

    // launch runners
    let cancel_token = tokio_util::sync::CancellationToken::new();

    let mut exit_rx = match args.mode {
        Mode::Client => {
            // running as CLIENT
            client_setup(listen_addr, dst_addr, cancel_token.clone()).await?
        }
        Mode::Server => {
            // running as SERVER
            server_setup(listen_addr, dst_addr, cancel_token.clone()).await?
        }
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

// ================================================================ //
//                            Client                                //
// ================================================================ //

async fn client_setup(
    listen_addr: SocketAddr,
    remote_addr: SocketAddr,
    cancel_token: CancellationToken,
) -> Result<oneshot::Receiver<bool>> {
    let obfs4_name = Obfs4PT::name();
    let (tx, rx) = oneshot::channel::<bool>();

    let mut listeners = Vec::new();

    let builder = Obfs4PT::client_builder();
    let listener = tokio::net::TcpListener::bind(CLIENT_SOCKS_ADDR).await?;

    listeners.push(client_accept_loop(
        listener,
        builder,
        remote_addr,
        cancel_token.clone(),
    ));

    // spawn a task that runs and monitors the progress of the listeners.
    tokio::spawn(async move {
        let total_len = listeners.len();
        let mut running = total_len;

        // launch all listener futures
        let mut pt_set = JoinSet::new();
        for fut in listeners {
            pt_set.spawn(fut);
        }

        // if any of the listeners exit, handle it
        while let Some(res) = pt_set.join_next().await {
            running -= 1;
            if let Err(e) = res {
                warn!("listener failed: {e}");
            }
            info!("{running}/{total_len} listeners running");
        }

        // if all listeners exit then we can send the tx signal.
        tx.send(true).unwrap()
    });

    Ok(rx)
}

async fn client_accept_loop<C>(
    listener: TcpListener,
    builder: impl ptrs::ClientBuilderByTypeInst<TcpStream, ClientPT = C> + Send + 'static,
    remote_addr: SocketAddr,
    cancel_token: CancellationToken,
) -> Result<()>
where
    // the provided client builder should build the C ClientTransport.
    C: ptrs::ClientTransport<TcpStream, std::io::Error> + 'static,
{
    let pt_name = C::method_name();
    info!(
        "{pt_name} client accept loop launched listening on: {}",
        listener.local_addr()?
    );
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
                tokio::spawn(client_handle_connection(conn, builder.clone(), remote_addr, client_addr));
                // tokio::spawn(client_handle_connection( conn, builder.build(), proxy_uri.clone(), client_addr));
            }
        }
    }

    Ok(())
}

/// This function assumes that the provided connection / socket manages reconstruction
/// and reliability before passing to this layer.
async fn client_handle_connection<In, C>(
    mut conn: In,
    builder: impl ptrs::ClientBuilderByTypeInst<TcpStream, ClientPT = C>,
    remote_addr: SocketAddr,
    client_addr: SocketAddr,
) -> Result<()>
where
    // the provided T must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Unpin,
    // the provided client builder should build the C ClientTransport.
    C: ptrs::ClientTransport<TcpStream, std::io::Error>,
{
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
            warn!(
                address = sensitive(client_addr).to_string(),
                "handshake failed: {e:#?}"
            );
            return Err(obfs4::Error::from(e.to_string())).context("handshake failed");
        }
        Ok(c) => c,
    };

    if let Err(e) = copy_bidirectional(&mut conn, &mut pt_conn).await {
        warn!(
            addres = sensitive(client_addr).to_string(),
            "tunnel closed with error: {e:#?}"
        );
    }
    Ok(())
}

/// This function assumes that the provided connection / socket manages reconstruction
/// and reliability before passing to this layer.
///
/// proxy_uri (currently unused) is meant to indicate that the outgoing connection
/// should be made through _another_ proxy based on the proxy uri. This is relatively
/// easy in golang, but I am not sure how easy it will be here. I believe this is
/// a rather uncommon option so it is left unimplemented for now.
async fn client_handle_connection_clientpt<In, C>(
    conn: In,
    pt_client: C,
    remote_addr: SocketAddr,
    client_addr: SocketAddr,
) -> Result<()>
where
    // the provided T must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Unpin,
    // the provided B must implement the Client Builder interface for T
    C: ptrs::ClientTransport<TcpStream, std::io::Error>,
{
    let mut config: fast_socks5::server::Config<SimpleUserPassword> =
        fast_socks5::server::Config::default();
    // config.set_skip_auth(true);
    let mut socks5_conn = fast_socks5::server::Socks5Socket::new(conn, Arc::new(config));

    // let mut socks5_conn = socks5_conn.upgrade_to_socks5().await?;
    let target_addr = socks5_conn
        .target_addr()
        .ok_or(BridgeLineParseError)
        .context("missing remote address in request")?;

    // TODO: get args from the socks request username:Password if it exists.
    // This seems non-trivial to match against the golang obfs4 implementation.
    // Maybe implement my own thing that implements the `Authenticate` trait?
    // Maybe work with the tor_socksproto package?
    //
    // Pluggable transports use the username/password field to pass
    // per-connection arguments.  The fields contain ASCII strings that
    // are combined and then parsed into key/value pairs.
    // argStr := string(uname)
    // if !(plen == 1 && passwd[0] == 0x00) {
    let args: Option<ptrs::args::Args> = match socks5_conn.auth() {
        AuthenticationMethod::Password { username, password } => {
            if username.is_empty() {
                socks5_conn.flush().await?;
                socks5_conn.shutdown().await?;
                return Err(anyhow!("username with 0 length"));
            }
            if password.is_empty() {
                socks5_conn.flush().await?;
                socks5_conn.shutdown().await?;
                return Err(anyhow!("password with 0 length"));
            }

            let mut arg_string = username.clone();
            // tor will set the password to 'NUL', if the field doesn't contain any
            // actual argument data.
            if !(password.len() == 1 && password.as_bytes().first().copied() == Some(0x00)) {
                arg_string.push_str(password);
            }

            match ptrs::args::Args::from_str(&arg_string) {
                Ok(a) => Some(a),
                Err(e) => {
                    return Err(anyhow!(
                        "failed to parse provided args \"{arg_string}\": {e}"
                    ))
                }
            }
        }
        AuthenticationMethod::None => None,
        _ => return Err(anyhow!("negotiated unsupported authentication method")),
    };

    let remote = tokio::net::TcpStream::connect(remote_addr);

    // build the pluggable transport client and then dial, completing the
    // connection and handshake when the `wrap(..)` is await-ed.
    let mut pt_conn = match pt_client.establish(Box::pin(remote)).await {
        Ok(c) => c,
        Err(e) => {
            warn!(
                address = sensitive(client_addr).to_string(),
                "handshake failed: {e:#?}"
            );
            return Err(obfs4::Error::from(e.to_string())).context("handshake failed");
        }
    };

    if let Err(e) = copy_bidirectional(&mut socks5_conn.into_inner(), &mut pt_conn).await {
        warn!(
            addres = sensitive(client_addr).to_string(),
            "tunnel closed with error: {e:#?}"
        );
    }

    Ok(())
}

// ================================================================ //
//                            Server                                //
// ================================================================ //

async fn server_setup(
    listen_addr: SocketAddr,
    remote_addr: SocketAddr,
    cancel_token: CancellationToken,
) -> Result<oneshot::Receiver<bool>> {
    let obfs4_name = Obfs4PT::name();

    let (tx, rx) = oneshot::channel::<bool>();

    let mut listeners = Vec::new();

    let options = ptrs::args::Args::new();

    let mut builder = Obfs4PT::server_builder();
    <obfs4::obfs4::ServerBuilder as ptrs::ServerBuilder<TcpStream>>::options(
        &mut builder,
        &options,
    )?;
    let server = builder.build();
    // // TODO: I hate having to use the specific < > notation ^^ but I am not sure how to avoid it.
    // let server = builder
    //     .options(bind_addr.options)?
    //     .build();

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    listeners.push(server_listen_loop::<TcpStream, _>(
        listener,
        server,
        remote_addr,
        cancel_token.clone(),
    ));

    // spawn a task that runs and monitors the progress of the listeners.
    tokio::spawn(async move {
        let total_len = listeners.len();
        let mut running = total_len;

        // launch all listener futures
        let mut pt_set = JoinSet::new();
        for fut in listeners {
            pt_set.spawn(fut);
        }

        // if any of the listeners exit, handle it
        while let Some(res) = pt_set.join_next().await {
            running -= 1;
            if let Err(e) = res {
                warn!("listener failed: {e}");
            }
            info!("{running}/{total_len} listeners running");
        }

        // if all listeners exit then we can send the tx signal.
        tx.send(true).unwrap()
    });

    Ok(rx)
}

async fn server_listen_loop<In, S>(
    listener: TcpListener,
    server: S,
    remote_addr: SocketAddr,
    cancel_token: CancellationToken,
) -> Result<()>
where
    // the provided In must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    // The provided S must be usable as a Pluggable Transport Server.
    S: ptrs::ServerTransport<In> + Send + Sync + ptrs::ServerTransport<TcpStream> + 'static,
    <S as ptrs::ServerTransport<In>>::OutErr: 'static,
{
    let method_name = <S as ServerTransport<In>>::method_name();
    info!(
        "{method_name} server accept loop launched listening on: {}",
        listener.local_addr()?
    );
    let server = Arc::new(server);
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("{method_name} received shutdown signal - closing listener");
                break
            }
            res = listener.accept() => {
                let (mut conn, client_addr) = match res {
                    Err(e) => {
                       error!("{method_name} closing listener - failed to accept tcp connection {e}");
                       break;
                   }
                   Ok(c) => c,
               };
               debug!("accepted new connection -> {}:{}", sensitive(client_addr.ip()), client_addr.port());
               tokio::spawn(server_handle_connection(
                   conn,
                   server.clone(),
                   remote_addr,
                   client_addr,
               ));
            }
        }
    }

    Ok(())
}

async fn server_handle_connection<In, S>(
    mut conn: In,
    server: Arc<S>,
    remote_addr: SocketAddr,
    client_addr: SocketAddr,
) -> Result<()>
where
    // the provided In must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    // The provided S must be usable as a Pluggable Transport Server.
    S: ptrs::ServerTransport<In> + Send + Sync + ptrs::ServerTransport<TcpStream>,
    <S as ptrs::ServerTransport<In>>::OutErr: 'static,
{
    // let mut conn_pt = server.reveal(conn).await.context("server handshake failed {client_addr}")?;

    // let mut conn_or = server.connect_to_or().await?;
    let mut remote_conn = TcpStream::connect(remote_addr).await?;

    if let Err(e) = copy_bidirectional(&mut conn, &mut remote_conn).await {
        warn!(
            address = sensitive(client_addr).to_string(),
            "tunnel closed with error {e:#?}"
        )
    }

    Ok(())
}
