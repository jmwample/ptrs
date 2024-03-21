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
use clap::Parser;
use fast_socks5::{
    server::{DenyAuthentication, SimpleUserPassword},
    util::target_addr::TargetAddr,
    AuthenticationMethod,
};
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal::unix::SignalKind,
    sync::oneshot,
};
// use tokio_stream::StreamExt;
use safelog::sensitive;
use tokio::task::JoinSet;
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

use std::{env, net::SocketAddr, str::FromStr, sync::Arc};

// /// The location where the obfs4 server will store its state
// const SERVER_STATE_LOCATION: &str = "/tmp/arti-pt";
// /// The location where the obfs4 client will store its state
// const CLIENT_STATE_LOCATION: &str = "/tmp/arti-pt-client";

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

/// initialize the logging receiver(s) for things to be logged into using the
/// tracing / tracing_subscriber libraries
// TODO: GeoIP. Json for file log writer.
fn init_logging_recvr(
    enable: bool,
    should_scrub: bool,
    level_str: &str,
    statedir: &str,
) -> Result<()> {
    if should_scrub {
        safelog::enforce_safe_logging();
    } else {
        safelog::disable_safe_logging();
    }

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

fn resolve_target_addr(addr: &TargetAddr) -> Result<SocketAddr> {
    match addr {
        TargetAddr::Ip(sa) => Ok(*sa),
        TargetAddr::Domain(_, _) => {
            // this will always fail because ptrs does not do dns lookups.
            ptrs::resolve_addr(format!("{addr}")).context("domain resolution failed")
        }
    }
}

/// Main function, ties everything together and parses arguments etc.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Make state directory
    let statedir = ptrs::make_state_dir()?;

    // launch tracing subscriber with filter level
    init_logging_recvr(
        args.enable_logging,
        !args.unsafe_logging,
        &args.log_level,
        &statedir,
    )?;

    let cancel_token = tokio_util::sync::CancellationToken::new();

    // launch runners
    let mut exit_rx = if ptrs::is_client()? {
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

// ================================================================ //
//                            Client                                //
// ================================================================ //

async fn client_setup(
    statedir: &str,
    cancel_token: CancellationToken,
) -> Result<oneshot::Receiver<bool>> {
    let obfs4_name = Obfs4PT::name();
    let client_pt_info = ptrs::ClientInfo::new()?;
    let proxy_uri = client_pt_info.uri.ok_or(BridgeLineParseError)?;
    let (tx, rx) = oneshot::channel::<bool>();

    let mut listeners = Vec::new();

    // This only launches lyrebird / obfs4 for now and doesn't track other PT types
    for name in client_pt_info.methods {
        info!(name);
        if name != obfs4_name {
            warn!("no such transport is supported");
            continue;
        }

        let builder = Obfs4PT::client_builder();
        let listener = tokio::net::TcpListener::bind(CLIENT_SOCKS_ADDR).await?;

        listeners.push(client_accept_loop(
            listener,
            builder,
            proxy_uri.clone(),
            cancel_token.clone(),
        ));
    }

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
    proxy_uri: url::Url,
    cancel_token: CancellationToken,
) -> Result<()>
where
    // the provided client builder should build the C ClientTransport.
    C: ptrs::ClientTransport<TcpStream, std::io::Error> + 'static,
{
    let pt_name = C::method_name();
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
                tokio::spawn(client_handle_connection(conn, builder.clone(), proxy_uri.clone(), client_addr));
                // tokio::spawn(client_handle_connection( conn, builder.build(), proxy_uri.clone(), client_addr));
            }
        }
    }

    Ok(())
}

/// This function assumes that the provided connection / socket manages reconstruction
/// and reliability before passing to this layer.
async fn client_handle_connection<In, C>(
    conn: In,
    builder: impl ptrs::ClientBuilderByTypeInst<TcpStream, ClientPT = C>,
    _proxy_uri: url::Url,
    client_addr: SocketAddr,
) -> Result<()>
where
    // the provided T must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Unpin,
    // the provided client builder should build the C ClientTransport.
    C: ptrs::ClientTransport<TcpStream, std::io::Error>,
{
    let mut config: fast_socks5::server::Config<SimpleUserPassword> =
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
    //     warn!(address=sensitive(client_addr).to_string(), "failed to authenticate client socks5 conn");
    //     return
    // }

    let remote_addr = resolve_target_addr(target_addr).context("no remote address")?;

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

    if let Err(e) = copy_bidirectional(&mut socks5_conn.into_inner(), &mut pt_conn).await {
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
    _proxy_uri: url::Url,
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

    let remote_addr = resolve_target_addr(target_addr).context("no remote address")?;

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
    statedir: &str,
    cancel_token: CancellationToken,
) -> Result<oneshot::Receiver<bool>> {
    let obfs4_name = Obfs4PT::name();

    let server_info = ptrs::ServerInfo::new()?;
    let (tx, rx) = oneshot::channel::<bool>();

    let mut listeners = Vec::new();

    for bind_addr in server_info.bind_addrs {
        info!(bind_addr.method_name);
        if bind_addr.method_name != obfs4_name {
            warn!("no such transport is supported");
            continue;
        }

        let mut builder = Obfs4PT::server_builder();
        <obfs4::obfs4::ServerBuilder as ptrs::ServerBuilder<TcpStream>>::statefile_location(
            &mut builder,
            statedir,
        )?;
        <obfs4::obfs4::ServerBuilder as ptrs::ServerBuilder<TcpStream>>::options(
            &mut builder,
            &bind_addr.options,
        )?;
        let server = builder.build();
        // // I hate having to use the specific < > notation ^^ but I am not sure how to avoid it.
        // let server = builder.statefile_location(statedir)?
        //     .options(bind_addr.options)?
        //     .build();

        let listener = tokio::net::TcpListener::bind(bind_addr.addr).await?;
        listeners.push(server_listen_loop::<TcpStream, _>(
            listener,
            server,
            cancel_token.clone(),
        ));
    }

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
               tokio::spawn(server_handle_connection(
                   conn,
                   server.clone(),
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
    let mut conn_or = TcpStream::connect("127.0.0.1:8000").await?;

    if let Err(e) = copy_bidirectional(&mut conn, &mut conn_or).await {
        warn!(
            address = sensitive(client_addr).to_string(),
            "tunnel closed with error {e:#?}"
        )
    }

    Ok(())
}
