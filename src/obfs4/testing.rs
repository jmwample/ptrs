use super::*;
use crate::Result;

#[tokio::test]
async fn public_iface() -> Result<()> {
    let (mut c, mut s) = tokio::io::duplex(65_536);

    let mut o4_server = proto::Server::default();
    let o4s_stream = o4_server.wrap(&mut s);

    // tokio::spawn(async move {
    //     let (r, w) = tokio::io::split(o4s_stream);
    //     tokio::io::copy(r, w).await.unwrap();
    // });

    let o4_client = proto::Client::default();
    let o4c_stream = o4_client.wrap(&mut c)?;

    Ok(())
}
