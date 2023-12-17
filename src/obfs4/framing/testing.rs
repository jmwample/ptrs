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
use crate::test_utils::init_subscriber;
use crate::Result;

use bytes::{Buf, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use rand::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, info, trace};

fn random_key_material() -> [u8; KEY_MATERIAL_LENGTH] {
    let mut r = [0_u8; KEY_MATERIAL_LENGTH];
    getrandom::getrandom(&mut r);
    r
}

#[test]
fn encode_decode() -> Result<()> {
    init_subscriber();
    let message = b"Hello there".to_vec();
    let mut key_material = [0_u8; KEY_MATERIAL_LENGTH];
    rand::thread_rng().fill(&mut key_material[..]);

    let mut codec = Obfs4Codec::new(key_material.clone(), key_material.clone());

    let mut b = bytes::BytesMut::with_capacity(LENGTH_LENGTH + PACKET_OVERHEAD + message.len());
    let mut input = BytesMut::new();
    build_and_marshall(&mut input, PacketType::Payload, message.clone(), 0);
    codec.encode(&mut input, &mut b)?;

    let Message::Payload(plaintext) = codec.decode(&mut b)?.expect("failed to decode") else {
        panic!("f")
    };
    assert_eq!(plaintext, message);

    Ok(())
}

#[tokio::test]
async fn basic_flow() -> Result<()> {
    init_subscriber();
    let message = b"Hello there";
    let key_material = [0_u8; KEY_MATERIAL_LENGTH];

    try_flow(key_material, message.to_vec()).await
}

#[tokio::test]
async fn oversized_flow() -> Result<()> {
    init_subscriber();
    let frame_len = MAX_FRAME_PAYLOAD_LENGTH + 1;
    let oversized_messsage = vec![65_u8; frame_len];
    let key_material = [0_u8; KEY_MATERIAL_LENGTH];

    let mut b = bytes::BytesMut::with_capacity(2_usize.pow(13));
    let mut codec = Obfs4Codec::new(key_material.clone(), key_material.clone());
    let mut src = Bytes::from(oversized_messsage);
    let res = codec.encode(&mut src, &mut b);

    assert_eq!(
        res.unwrap_err(),
        FrameError::InvalidPayloadLength(frame_len)
    );
    Ok(())
}

#[tokio::test]
async fn many_sizes_flow() -> Result<()> {
    init_subscriber();
    for l in MAX_FRAME_PAYLOAD_LENGTH - 6..(MAX_FRAME_PAYLOAD_LENGTH - PACKET_OVERHEAD) {
        let key_material = random_key_material();
        let message = vec![65_u8; l];
        debug!("\n\n{l}, {}", message.len());
        tokio::select! {
            res = try_flow(key_material, message) => {
                res?;
            },
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(3)) => {
                panic!("timed out for {l}");
            },
        }
    }
    Ok(())
}

async fn try_flow(key_material: [u8; KEY_MATERIAL_LENGTH], msg: Vec<u8>) -> Result<()> {
    let (c, s) = tokio::io::duplex(16 * 1024);

    let msg_s = msg.clone();

    tokio::spawn(async move {
        let codec = Obfs4Codec::new(key_material.clone(), key_material.clone());
        let message = &msg_s;

        let (mut sink, mut input) = codec.framed(s).split();

        while let Some(Ok(event)) = input.next().await {
            if let Message::Payload(m) = event {
                assert_eq!(&m, &message.clone());
                trace!("Event {:?}", String::from_utf8(m.clone()).unwrap());

                let mut b = BytesMut::new();
                build_and_marshall(&mut b, PacketType::Payload, &m, 0);
                sink.send(b).await.expect("server response failed");
            } else {
                panic!("failed while reading from codec");
            }
        }
    });

    let mut message = BytesMut::new();
    build_and_marshall(&mut message, super::PacketType::Payload, &msg, 0);

    let client_codec = Obfs4Codec::new(key_material, key_material);
    let (mut c_sink, mut c_stream) = client_codec.framed(c).split();

    c_sink.send(&mut message).await.expect("client send failed");
    trace!("client write success");

    if let Message::Payload(m) = c_stream
        .next()
        .await
        .expect(&format!(
            "you were supposed to call me back!, {} (max={})",
            message.len(),
            MAX_FRAME_PAYLOAD_LENGTH
        ))
        .expect("an error occured when you called back")
    {
        // skip over length field in the Payload message
        assert_eq!(&m, &msg);
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

#[tokio::test]
async fn double_encode_decode() -> Result<()> {
    println!();
    init_subscriber();
    let (c, s) = tokio::io::duplex(16 * 1024);
    let msg = b"j dkja ;ae ;awena woea;wfel rfawe";
    let plain_msg = Message::Payload(msg.to_vec());
    let mut pkt1 = BytesMut::new();
    plain_msg.marshall(&mut pkt1);
    let mut pkt2 = pkt1.clone();

    let key_material = random_key_material();
    let client_codec = Obfs4Codec::new(key_material, key_material);
    let (mut c_sink, mut c_stream) = client_codec.framed(c).split();
    let server_codec = Obfs4Codec::new(key_material, key_material);
    let (mut s_sink, mut s_stream) = server_codec.framed(s).split::<Bytes>();

    c_sink.send(&mut pkt1).await.expect("client send failed");
    c_sink.send(&mut pkt2).await.expect("client send failed");

    for i in 0..2 {
        let Some(Ok(event)) = s_stream.next().await else {
            panic!("read none!!!")
        };
        if let Message::Payload(m) = event {
            assert_eq!(&m, &msg.clone());
            trace!("Event {:?}", String::from_utf8(m.clone()).unwrap());

            send_payload(&mut s_sink, &m)
                .await
                .expect("server response failed");
        } else {
            panic!("failed while reading from codec");
        }
    }

    for i in 0..2 {
        if let Message::Payload(m) = c_stream
            .next()
            .await
            .expect(&format!(
                "you were supposed to call me back!, {} (max={})",
                msg.len(),
                MAX_FRAME_PAYLOAD_LENGTH
            ))
            .expect("an error occured when you called back")
        {
            // skip over length field in the Payload message
            assert_eq!(&m, &msg);
            trace!("client read success");
        } else {
            panic!("failed while reading from codec");
        }
    }

    Ok(())
}
