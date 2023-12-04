use super::*;
use crate::Result;

use crate::test_utils::init_subscriber;

use tracing::trace;

#[tokio::test]
async fn public_iface() -> Result<()> {
    init_subscriber();
    let (mut c, mut s) = tokio::io::duplex(65_536);

    let mut o4_server = proto::Server::new_from_random();
    trace!("server created");
    let client_config = o4_server.client_params();
    trace!("client params extracted from server");

    tokio::spawn(async move {
        trace!("server listening for handshake");
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        trace!("server handshake completed");
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = proto::Client::from_params(client_config);
    trace!("client created - awaiting handshake");
    let o4c_stream = o4_client.wrap(&mut c).await?;
    trace!("client handshake completed");

    Ok(())
}
