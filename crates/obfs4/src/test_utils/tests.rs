// use crate::{stream::Stream, Error, Result};
use crate::Result;

// use futures::join;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use tracing::debug;
/*
///
///                       write  ===================>  encode  ===================>  >|
///                       read   <===================  decode  <===================  <| echo
///
///        [ loop Buffer ] -> | source | -> | plaintext | -> | ciphertext | -> | echo |
///                                     pipe                               pipe
///
#[allow(non_snake_case)]
pub async fn duplex_end_to_end_1_MB<'a, A, B>(
    source: A,
    mut plaintext: A,
    mut ciphertext: B,
    echo: B,
    duplex: impl DuplexTransform<A, B> + 'a,
) -> Result<(u64, u64)>
where
    A: Stream<'a> + 'a,
    B: Stream<'a> + 'a,
{
    let proxy_task = async {
        let r = duplex
            .copy_bidirectional(&mut plaintext, &mut ciphertext)
            .await;
        plaintext.flush().await?;
        plaintext.shutdown().await?;
        std::thread::sleep(std::time::Duration::from_millis(100));
        ciphertext.flush().await?;
        ciphertext.shutdown().await?;
        debug!("proxy finished");
        r
    };

    let (echo_r, echo_w) = tokio::io::split(echo);
    let echo_task = echo_fn(echo_r, echo_w);

    let (source_r, source_w) = tokio::io::split(source);
    let trash_task = trash(source_r);

    let client_write = write_and_close(source_w);

    let (trash_result, proxy_result, echo_result, client_result) =
        join!(trash_task, proxy_task, echo_task, client_write);
    echo_result.unwrap(); // ensure result is Ok - otherwise result is useless.
    assert_eq!(client_result?, 1024 * 1024);
    assert_eq!(trash_result?, 1024 * 1024);

    debug!("test_complete");
    let out = proxy_result.map_err(Error::IOError);
    debug!("returning");
    out
}
*/

async fn echo_fn<'a, A, B>(mut r: ReadHalf<A>, mut w: WriteHalf<B>) -> std::io::Result<()>
where
    A: AsyncRead + Unpin + 'a,
    B: AsyncWrite + Unpin + 'a,
{
    let _n = tokio::io::copy(&mut r, &mut w).await?;
    _ = w.write(&[]).await?;
    w.flush().await?;
    w.shutdown().await?;
    debug!("echo_fn finished");
    Ok(())
}

async fn write_and_close<'a, A: AsyncWrite + Unpin + 'a>(
    mut w: WriteHalf<A>,
) -> std::io::Result<usize> {
    let write_me = vec![0_u8; 1024];
    let mut n = 0;
    for _ in 0..1024 {
        n += w.write(&write_me).await?;
    }
    n += w.write(&[]).await?;
    w.flush().await?;
    assert_eq!(n, 1024 * 1024);

    debug!("finished writing... sleeping 1s");
    std::thread::sleep(std::time::Duration::from_millis(100));
    w.shutdown().await?;
    debug!("writer closed");
    Ok(n)
}

async fn trash<'a, A: AsyncRead + Unpin + 'a>(mut r: ReadHalf<A>) -> Result<u64> {
    let out_file = tokio::fs::File::create("/dev/null").await.unwrap();
    let mut out_file = tokio::io::BufWriter::new(out_file);
    let n = tokio::io::copy(&mut r, &mut out_file).await.unwrap();
    debug!("trash finished");
    Ok(n)
}
