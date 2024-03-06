use crate::obfs4::{framing::*, proto::IAT};

use tokio::io::AsyncWrite;
use tokio::time;
use tokio_util::bytes::BytesMut;

///
pub struct FrameBuilder(FrameBuilderV<V1>);

const SEND_QUEUE_BUF_SIZE: usize = usize::pow(2, 15);

impl FrameBuilder {
    pub fn new(iat_mode: IAT) -> Self {
        Self {
            0: FrameBuilderV {
                iat_mode,
                write_queue: BytesMut::with_capacity(SEND_QUEUE_BUF_SIZE),
                _ver: V1 {
                    non_payload_queue: vec![],
                    last_heartbeat: time::Instant::now(),
                },
            },
        }
    }

    pub fn downgrade(mut self) -> FrameBuilderV<V0> {
        self.0.downgrade()
    }
}

///
struct V0 {}

///
struct V1 {
    non_payload_queue: Vec<Messages>,

    last_heartbeat: time::Instant,
}

trait FrameSenderVersion {}
impl FrameSenderVersion for V0 {}
impl FrameSenderVersion for V1 {}

///
struct FrameBuilderV<S: FrameSenderVersion> {
    ///
    iat_mode: IAT,

    ///
    write_queue: BytesMut,

    ///
    _ver: S,
}

impl FrameBuilderV<V1> {
    pub fn downgrade(self) -> FrameBuilderV<V0> {
        FrameBuilderV {
            iat_mode: self.iat_mode,
            write_queue: self.write_queue,
            _ver: V0 {},
        }
    }
}

impl AsyncWrite for FrameBuilderV<V1> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        todo!()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        todo!()
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        todo!()
    }
}

impl FrameBuilderV<V0> {
    pub fn build_and_marshall() {}
}

impl AsyncWrite for FrameBuilderV<V0> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        todo!()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        todo!()
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        todo!()
    }
}

#[cfg(test)]
mod testing {
    use super::*;
    use tokio::io::AsyncWriteExt;

    const MAX_FRAME_LENGTH: usize = MAX_SEGMENT_LENGTH - LENGTH_LENGTH;

    #[tokio::test]
    async fn build_frame_v0() {
        let test_msg_lengths = [0, 1, 2, MAX_FRAME_PAYLOAD_LENGTH, MAX_FRAME_LENGTH, MAX_SEGMENT_LENGTH,];

        let mut fb = FrameBuilder::new(IAT::Off).downgrade();

        for length in test_msg_lengths {
            let msg = vec![0_u8; length];

            fb.write_all(&msg).await.unwrap();
        }
    }

}
