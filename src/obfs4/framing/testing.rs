/// testing out tokio_util::codec for building transports.
///
/// useful links:
/// - https://dev.to/jtenner/creating-a-tokio-codec-1f0l
///     - example telnet implementation using codecs
///     - https://github.com/jtenner/telnet_codec
///
/// - https://docs.rs/tokio-util/latest/tokio_util/codec/index.html
///     - tokio_util codec docs
///

use super::*;
use crate::Result;

use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{Encoder,Decoder};
use bytes::{BytesMut, Buf};
use futures::{Sink, Stream, StreamExt, SinkExt};



#[tokio::test]
async fn framing_flow() -> Result<()> {

    let (c,s) = tokio::io::duplex(16*1024);

    tokio::spawn(async move {
        let codec = Obfs4Codec::new();

        let (mut sink, mut input) = codec.framed(s).split();

        while let Some(Ok(event)) = input.next().await {
            println!("Event {:?}", event);
            sink.send(event).await.expect("server response failed");
        }
    });

    let message = "Hello there";
    let client_codec = Obfs4Codec::new();
    let (mut c_sink, mut c_stream) = client_codec.framed(c).split();

    c_sink.send(message.into()).await.expect("client send failed");

    let m: String = c_stream.next().await
        .expect("you were supposed to call me back!")
        .expect("an error occured when you called back");

    assert_eq!(m, message);

    Ok(())
}

