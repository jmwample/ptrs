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
use crate::test_utils::init_subscriber;

use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{Encoder,Decoder};
use bytes::{BytesMut, Buf};
use futures::{Sink, Stream, StreamExt, SinkExt};
use tracing::{debug,trace};

fn random_key_material() -> [u8; KEY_MATERIAL_LENGTH] {
    let mut r = [0_u8; KEY_MATERIAL_LENGTH];
    getrandom::getrandom(&mut r);
    r
}

#[tokio::test]
async fn basic_flow() -> Result<()> {
    // init_subscriber();
    let message = b"Hello there";
    let key_material = [0_u8; KEY_MATERIAL_LENGTH];

    try_flow(key_material, message.to_vec()).await
}

#[tokio::test]
async fn oversized_flow() -> Result<()> {
    let frame_len = MAXIMUM_FRAME_PAYLOAD_LENGTH + 1;
    let oversized_messsage = vec![65_u8; frame_len];
    let key_material = [0_u8; KEY_MATERIAL_LENGTH];

    let mut b = bytes::BytesMut::with_capacity(2_usize.pow(13));
    let mut codec = Obfs4Codec::new(key_material.clone());
    let res = codec.encode(Obfs4Message::ProxyPayload(oversized_messsage),&mut b);

    assert_eq!(res.unwrap_err(), FrameError::InvalidPayloadLength(frame_len));
    Ok(())
}

#[tokio::test]
async fn many_sizes_flow() -> Result<()> {
    // init_subscriber();
    for l in 0 .. (MAXIMUM_FRAME_PAYLOAD_LENGTH) {
        let key_material = random_key_material();
        let oversized_messsage = vec![65_u8; l];
        debug!("{l}");
        tokio::select! {
            res = try_flow(key_material, oversized_messsage) => {
                res?;
            },
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(3)) => {
                panic!("timed out for {l}");
            }, 
        }
    }
    Ok(())
}


async fn try_flow(key_material: [u8; KEY_MATERIAL_LENGTH], msg:  Vec<u8>) -> Result<()> {
    let (c,s) = tokio::io::duplex(16*1024);

    let msg_s = msg.clone();

    tokio::spawn(async move {
        let codec = Obfs4Codec::new(key_material.clone());
        let message = &msg_s;

        let (mut sink, mut input) = codec.framed(s).split();

        while let Some(Ok(event)) = input.next().await {

            if let Obfs4Message::ProxyPayload(m) = &event {
                assert_eq!(m, &message.clone());
                trace!("Event {:?}", String::from_utf8(m.clone()).unwrap());
            } else {
                panic!("failed while reading from codec");
            }

            sink.send(event).await.expect("server response failed");
        }
    });

    let message = &msg;
    let client_codec = Obfs4Codec::new(key_material);
    let (mut c_sink, mut c_stream) = client_codec.framed(c).split();

    c_sink.send(Obfs4Message::ProxyPayload(message.to_vec())).await.expect("client send failed");
    trace!("client write success");

    if let Obfs4Message::ProxyPayload(m) = c_stream.next().await
        .expect(&format!("you were supposed to call me back!, {} (max={})", message.len(), MAXIMUM_FRAME_PAYLOAD_LENGTH))
        .expect("an error occured when you called back") {
        assert_eq!(&m, message);
        trace!("client read success");
    } else {
        panic!("failed while reading from codec");
    }

    Ok(())
}

#[test]
fn nonce_wrap() -> Result<()> {
    let mut nb = NonceBox::new([0_u8; NONCE_PREFIX_LENGTH]);
    nb.counter = u64::MAX;

    assert_eq!(nb.next().unwrap_err(), FrameError::NonceCounterWrapped);
    Ok(())
}
