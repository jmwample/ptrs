use super::*;
use crate::Result;

use crate::test_utils::init_subscriber;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, trace};

#[tokio::test]
async fn public_iface() -> Result<()> {
    init_subscriber();
    let message = b"awoewaeojawenwaefaw lfawn;awe da;wfenalw fawf aw";
    let (mut c, mut s) = tokio::io::duplex(65_536);

    let mut o4_server = proto::Server::new_from_random();
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = proto::Client::from_params(client_config);
    let mut o4c_stream = o4_client.wrap(&mut c).await?;

    o4c_stream.write(&message.clone()[..]).await?;

    let mut buf = vec![0_u8; message.len()];
    o4c_stream.read(&mut buf).await?;
    assert_eq!(&message[..], &buf, "{}", String::from_utf8(message.to_vec())?);

    Ok(())
}

#[tokio::test]
async fn public_handshake() -> Result<()> {
    init_subscriber();
    let (mut c, mut s) = tokio::io::duplex(65_536);

    let mut o4_server = proto::Server::new_from_random();
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
    });

    let o4_client = proto::Client::from_params(client_config);
    let o4c_stream = o4_client.wrap(&mut c).await?;

    Ok(())
}
