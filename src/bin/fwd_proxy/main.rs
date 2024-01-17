mod config;
mod handler;
mod socks5;

use config::{Cli, ProxyConfig};


use anyhow::Result;
use clap::Parser;
use tokio::{self, signal, sync::mpsc::channel};
use tokio_util::sync::CancellationToken;

use tracing::{debug, error};

#[tokio::main]
async fn main() -> std::result::Result<(), anyhow::Error> {
    // send recv channel so that we know when all tasks have closed cleanly
    let (send, mut recv) = channel(1);
    // shutdown signal to indicate to all active thread processes that they should close
    let shutdown_signal = CancellationToken::new();

    tokio::select! {
        // launch proxy runner based on the parsed config. If config parsing fails we fail and
        // return the parse error.
        out = parse_config()?.run(shutdown_signal.clone(), send.clone()) => {
            if let Err(e) = out {
                error!("encountered error:{:?}", e);
                panic!("\tshutting down");
            }
        },
        _ = signal::ctrl_c() => {
            // ctrl-c was pressed, so we'll set the shutdown signal
            debug!("ctrl-c pressed, shutting down");
            shutdown_signal.cancel();
        },
    };

    // Wait for the tasks to finish.
    //
    // We drop our sender first because the recv() call otherwise
    // sleeps forever.
    drop(send);

    // When every sender has gone out of scope, the recv call
    // will return with an error. We ignore the error.
    let _ = recv.recv().await;
    debug!("shutdown complete");
    Ok(())
}

/// Parse command-line arguments and execute the appropriate commands
pub fn parse_config() -> Result<ProxyConfig, anyhow::Error> {
    let conf: ProxyConfig = Cli::parse().try_into()?;
    Ok(conf)
}
