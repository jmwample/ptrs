use crate::handler::{EchoHandler, Handler, Socks5Handler};
use obfs::traits::Builder;

use std::{convert::TryFrom, default::Default, marker::PhantomData, net, str::FromStr, sync::Arc};

use anyhow::anyhow;
use clap::{Args, CommandFactory, Parser, Subcommand};
use obfs::obfs4::{ClientBuilder, Server};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn, Level};

pub const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:9000";
pub const DEFAULT_SERVER_ADDRESS: &str = "127.0.0.1:9001";
pub const DEFAULT_REMOTE_ADDRESS: &str = "127.0.0.1:9010";
pub const DEFAULT_LOG_LEVEL: Level = Level::INFO;

pub enum ProxyConfig<B> {
    Entrance(EntranceConfig<B>),
    Socks5Exit(ExitConfig<B, Socks5Handler>),
    EchoExit(ExitConfig<B, EchoHandler>),
}

impl<B: Builder + Default> ProxyConfig<B> {
    pub async fn run(
        self,
        close: CancellationToken,
        wait: Sender<()>,
    ) -> Result<(), anyhow::Error> {
        match self {
            ProxyConfig::Entrance(config) => config.run(close, wait).await,
            ProxyConfig::Socks5Exit(config) => Arc::new(config).run(close, wait).await,
            ProxyConfig::EchoExit(config) => Arc::new(config).run(close, wait).await,
        }
    }
}

pub struct EntranceConfig<B> {
    pt: String,
    pt_args: Vec<String>,

    listen_address: net::SocketAddr,
    remote_address: net::SocketAddr,

    level: Level,
    builder: B,
}

impl<B: Builder + Default> EntranceConfig<B> {
    pub async fn run(
        self,
        close: CancellationToken,
        _wait: Sender<()>,
    ) -> Result<(), anyhow::Error> {
        let listener = TcpListener::bind(self.listen_address).await.unwrap();
        info!("started local proxy client on {}", self.listen_address);

        let t_name = "obfs4";

        loop {
            let (in_stream, socket_addr) = listener.accept().await?;
            let client = ClientBuilder::from_params(self.pt_args.clone())?.build();
            trace!("new tcp connection {socket_addr}");

            let mut out_stream = TcpStream::connect(self.remote_address)
                .await
                .map_err(|e| anyhow!("failed to connect to remote: {}", e))?;

            let close_c = close.clone();
            tokio::spawn(async move {
                let mut in_stream = match client.wrap(Box::new(in_stream)).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("failed to wrap in_stream ->({socket_addr}): {:?}", e);
                        return;
                    }
                };

                debug!("connection sealer established ->{t_name}-[{socket_addr}]");
                tokio::select! {
                    _ = copy_bidirectional(&mut in_stream, &mut out_stream) => {}
                    _ = close_c.cancelled() => {
                        debug!("shutting down proxy thread for {socket_addr}");
                    }
                }
            });
        }
    }
}

impl<B: Builder + Default> Default for EntranceConfig<B> {
    fn default() -> Self {
        Self {
            pt: String::from("plain"),
            pt_args: vec![],

            listen_address: DEFAULT_LISTEN_ADDRESS.parse().unwrap(),
            remote_address: DEFAULT_REMOTE_ADDRESS.parse().unwrap(),
            level: DEFAULT_LOG_LEVEL,
            builder: B::default(),
        }
    }
}

pub struct ExitConfig<B, H> {
    pt: String,
    pt_args: Vec<String>,

    // handler: Handler,
    listen_address: net::SocketAddr,

    level: Level,
    builder: B,
    phantom_backend: PhantomData<H>,
}

impl<B: Builder + Default, H: Handler> ExitConfig<B, H> {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(
        self: Arc<Self>,
        close: CancellationToken,
        _wait: Sender<()>,
    ) -> Result<(), anyhow::Error> {
        let listener = TcpListener::bind(self.listen_address).await.unwrap();
        info!("started server listening on {}", self.listen_address);

        let server = Arc::new(Server::getrandom());
        println!(
            "{}\n{}",
            server.client_params(),
            server.client_params().as_opts()
        );

        let t_name = "obfs4";

        let sessions = &mut JoinSet::new();

        let close_c = close.clone();

        loop {
            tokio::select! {
                _ = close_c.cancelled() => {
                    break
                }
                r = sessions.join_next() => {
                    match r {
                        Some(Err(e)) => {
                            warn!("handler error: \"{e}\", session closed");
                        }
                        _ => {}
                    }
                }
                r = listener.accept() => {
                    let (stream, socket_addr) = match r {
                        Err(e) => {
                            warn!("connection listener returned error {e}");
                            close_c.cancel();
                            continue
                        }
                        Ok(s) => s,
                    };

                    debug!("new tcp connection {socket_addr}");

                    let close_c = close.clone();

                    let proxy_stream = match server.wrap(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("failed to wrap in_stream ->({socket_addr}): {:?}", e);
                            continue;
                        }
                    };

                    debug!("connection successfully opened ->{t_name}-[{socket_addr}]");
                    sessions.spawn(Self::H::handle(proxy_stream, close_c));
                }
            }
        }

        sessions.abort_all();
        let start = std::time::Instant::now();
        while !sessions.is_empty() && start.elapsed().as_millis() < 3000 {
            _ = sessions.join_next().await;
        }
        Ok(())
    }
}

impl<B: Default, H> Default for ExitConfig<B, H> {
    fn default() -> Self {
        Self {
            pt: String::from("plain"),
            pt_args: vec![],
            listen_address: DEFAULT_SERVER_ADDRESS.parse().unwrap(),
            level: DEFAULT_LOG_LEVEL,
            // handler: Handlers::Echo,
            builder: B::default(),
            phantom_backend: PhantomData,
        }
    }
}

impl<B: Builder + Default> TryFrom<Cli> for ProxyConfig<B> {
    type Error = anyhow::Error;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        match cli.command {
            Some(Commands::Server(args)) => {
                match &*args.backend {
                    "socks5" => {} // ExitConfig::<B, Socks5Handler>::new(),
                    "echo" => {}   // ExitConfig::<B, EchoHandler>::new(),
                    _ => return Err(anyhow!("unknown backend")),
                }

                let level = if args.debug {
                    Level::DEBUG
                } else if args.trace {
                    Level::TRACE
                } else {
                    Level::ERROR
                };

                tracing_subscriber::fmt().with_max_level(level).init();
                trace!("{:?}", args);

                // TODO: parse pt name and arguments.
                let pt = "".to_string();
                let pt_args = vec![];

                let listen_address = args.listen_addr.parse()?;

                match &*args.backend {
                    "socks5" => {
                        let config = ExitConfig {
                            pt,
                            pt_args,
                            listen_address,
                            level,
                            builder: B::default(),
                            phantom_backend: PhantomData,
                        };
                        Ok(ProxyConfig::Socks5Exit(config))
                    }
                    "echo" => {
                        let config = ExitConfig {
                            pt,
                            pt_args,
                            listen_address,
                            level,
                            builder: B::default(),
                            phantom_backend: PhantomData,
                        };
                        Ok(ProxyConfig::EchoExit(config))
                    }
                    _ => Err(anyhow!("unknown backend")),
                }
            }
            Some(Commands::Client(args)) => {
                let mut config = EntranceConfig::default();
                if args.debug {
                    config.level = Level::DEBUG;
                } else if args.trace {
                    config.level = Level::TRACE;
                }
                tracing_subscriber::fmt()
                    .with_max_level(config.level)
                    .init();
                trace!("{:?}", args);

                config.remote_address = args.remote.parse()?;
                config.listen_address = args.listen_addr.parse()?;

                // TODO: parse pt name and arguments.
                config.pt = "".to_string();
                config.pt_args = vec![];

                Ok(ProxyConfig::Entrance(config))
            }
            None => {
                Cli::command().print_help()?;
                std::process::exit(1);
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about="Proof of Concept proxy system for pluggable transports (PTRS)", long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the binary as the remote server
    Server(ServerArgs),

    /// Run the binary as the client-side proxy
    Client(ClientArgs),
}

#[derive(Args, Debug)]
struct ServerArgs {
    /// Address to listen for incoming client connections
    listen_addr: String,

    // /// pluggable transport by name
    // #[arg(short, long, default_value_t = String::from("plain"))]
    // transport: String,
    /// The backend handler to use ["echo", "socks5"]
    #[arg(short, long, default_value_t = String::from("echo"))]
    backend: String,

    /// Optional argument enabling debug logging
    #[arg(long, default_value_t = false, conflicts_with = "trace")]
    debug: bool,

    /// Optional argument enabling debug logging
    #[arg(long, default_value_t = false, conflicts_with = "debug")]
    trace: bool,

    /// pluggable transport argument(s)
    #[arg(name="PT_ARGS", num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    trailing: Vec<String>,
}

#[derive(Args, Debug)]
struct ClientArgs {
    /// Optional argument specifying the client_type, default to be Runner
    remote: String,

    /// Address to listen for incoming client connections
    #[arg(short, long, default_value_t=String::from(DEFAULT_LISTEN_ADDRESS))]
    listen_addr: String,

    // /// pluggable transport by name
    // #[arg(short, long, default_value_t = String::from("plain"))]
    // transport: String,
    /// Optional argument enabling debug logging
    #[arg(long, default_value_t = false, conflicts_with = "trace")]
    debug: bool,

    /// Optional argument enabling debug logging
    #[arg(long, default_value_t = false, conflicts_with = "debug")]
    trace: bool,

    /// pluggable transport argument(s)
    #[arg(name="PT_ARGS", num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    trailing: Vec<String>,
}
