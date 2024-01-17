use crate::handler::{EchoHandler, Handler};

use std::{convert::TryFrom, default::Default, net, str::FromStr};

use anyhow::anyhow;
use clap::{Args, CommandFactory, Parser, Subcommand};
use obfs::obfs4::proto::{Client, Server};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, Level};

pub const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:9000";
pub const DEFAULT_SERVER_ADDRESS: &str = "127.0.0.1:9001";
pub const DEFAULT_REMOTE_ADDRESS: &str = "127.0.0.1:9010";
pub const DEFAULT_LOG_LEVEL: Level = Level::INFO;

pub enum ProxyConfig {
    Entrance(EntranceConfig),
    Exit(ExitConfig),
}

impl ProxyConfig {
    pub async fn run(
        self,
        close: CancellationToken,
        wait: Sender<()>,
    ) -> Result<(), anyhow::Error> {
        match self {
            ProxyConfig::Entrance(config) => config.run(close, wait).await,
            ProxyConfig::Exit(config) => config.run(close, wait).await,
        }
    }
}

pub struct EntranceConfig {
    pt: String,
    pt_args: Vec<String>,

    listen_address: net::SocketAddr,
    remote_address: net::SocketAddr,

    level: Level,
}

impl EntranceConfig {
    pub async fn run(
        self,
        close: CancellationToken,
        _wait: Sender<()>,
    ) -> Result<(), anyhow::Error> {
        let listener = TcpListener::bind(self.listen_address).await.unwrap();
        info!("started local proxy client on {}", self.listen_address);

        let client = Client::from_params(ClientParams::parse()?);
        let t_name = "obfs4";

        loop {
            let (in_stream, socket_addr) = listener.accept().await?;
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

impl Default for EntranceConfig {
    fn default() -> Self {
        Self {
            pt: String::from("plain"),
            pt_args: vec![],

            listen_address: DEFAULT_LISTEN_ADDRESS.parse().unwrap(),
            remote_address: DEFAULT_REMOTE_ADDRESS.parse().unwrap(),
            level: DEFAULT_LOG_LEVEL,
        }
    }
}

pub struct ExitConfig {
    pt: String,
    pt_args: Vec<String>,
    handler: Handler,

    listen_address: net::SocketAddr,

    level: Level,
}

impl ExitConfig {
    pub async fn run(
        self,
        close: CancellationToken,
        _wait: Sender<()>,
    ) -> Result<(), anyhow::Error> {
        let listener = TcpListener::bind(self.listen_address).await.unwrap();
        info!("started server listening on {}", self.listen_address);

        let server = Server::from_params(ServerParams::parse("")?);
        let t_name = "obfs4";

        loop {
            let (stream, socket_addr) = listener.accept().await?;
            trace!("new tcp connection {socket_addr}");

            let close_c = close.clone();
            let handler = self.handler;
            let stream = match server.wrap(Box::new(stream)) {
                Ok(s) => s,
                Err(e) => {
                    error!("failed to wrap in_stream ->({socket_addr}): {:?}", e);
                    continue;
                }
            };
            debug!("connection successfully revealed ->{t_name}-[{socket_addr}]");
            tokio::spawn(handler.handle(stream, close_c));
        }
    }
}

impl Default for ExitConfig {
    fn default() -> Self {
        Self {
            pt: String::from("plain"),
            pt_args: vec![],
            listen_address: DEFAULT_SERVER_ADDRESS.parse().unwrap(),
            level: DEFAULT_LOG_LEVEL,
            handler: Handler::Echo(EchoHandler),
        }
    }
}

impl TryFrom<Cli> for ProxyConfig {
    type Error = anyhow::Error;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        match cli.command {
            Some(Commands::Server(args)) => {
                let mut config = ExitConfig::default();
                if args.debug {
                    config.level = Level::DEBUG;
                } else if args.trace {
                    config.level = Level::TRACE;
                }
                tracing_subscriber::fmt()
                    .with_max_level(config.level)
                    .init();
                trace!("{:?}", args);

                config.pt = "".to_string();
                config.pt_args = vec![];

                config.listen_address = args.listen_addr.parse()?;

                config.handler = Handler::from_str(&args.backend)
                    .map_err(|e| anyhow!("failed to parse backend: {:?}", e))?;

                Ok(ProxyConfig::Exit(config))
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
