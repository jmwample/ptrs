use crate::Result;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

// use std::pin::Pin;
// use std::task::{Context, Poll};
use std::time::Duration;

/// copies all data from the reader to a sink. If the reader closes before
/// the timeout due to na error or an EoF that result will be returned.
/// Otherwise if the timeout is reached, the stream will be shutdown
/// and the result of that shutdown will be returned.
///
/// TODO: determine if it is possible to empty / flush write buffer before
/// shutdown to ensure consistent RST / FIN behavior on shutdown.
pub async fn discard<S>(stream: S, d: Duration) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut r, mut w) = tokio::io::split(stream);
    let result = tokio::time::timeout(d, async move {
        tokio::io::copy(&mut r, &mut tokio::io::sink()).await
    })
    .await;
    if let Ok(r) = result {
        // Error Occurred in coppy or connection hit EoF which means the
        // connection should already be closed.
        r.map(|_| ()).map_err(|e| e.into())
    } else {
        // stream out -- connection may not be closed -- close manually.
        w.shutdown().await.map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    use tokio::io::AsyncWriteExt;
    use tokio::time::Instant;

    use super::*;

    #[tokio::test]
    async fn discard_and_close_after_delay() {
        let (mut c, s) = tokio::io::duplex(1024);
        let start = Instant::now();
        let d = Duration::from_secs(3);
        let expected_end = start + d;
        let discard_fut = discard(s, d);

        tokio::spawn(async move {
            const MSG: &'static str = "abcdefghijklmnopqrstuvwxyz";
            loop {
                if let Err(e) = c.write(MSG.as_bytes()).await {
                    assert!(Instant::now() > expected_end);
                    println!("closed with error {e}");
                    break;
                }
            }
        });

        discard_fut.await.unwrap();

        assert!(Instant::now() > expected_end);
    }
}
