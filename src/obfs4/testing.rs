use super::*;
use crate::{obfs4::proto::Server, test_utils::init_subscriber, Result};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace};

use std::cmp::Ordering;
use std::time::Duration;

#[tokio::test]
async fn public_handshake() -> Result<()> {
    init_subscriber();
    let (mut c, mut s) = tokio::io::duplex(65_536);

    let mut o4_server = Server::new_from_random();
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let _ = tokio::io::split(o4s_stream);
    });

    let o4_client = proto::Client::from_params(client_config);
    let _o4c_stream = o4_client.wrap(&mut c).await?;

    Ok(())
}

#[tokio::test]
async fn public_iface() -> Result<()> {
    init_subscriber();
    let message = b"awoewaeojawenwaefaw lfawn;awe da;wfenalw fawf aw";
    let (mut c, mut s) = tokio::io::duplex(65_536);

    let mut o4_server = Server::new_from_random();
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let mut o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        // let (mut r, mut w) = tokio::io::split(o4s_stream);
        // tokio::io::copy(&mut r, &mut w).await.unwrap();

        let mut buf = [0_u8; 50];
        let n = o4s_stream.read(&mut buf).await.unwrap();
        o4s_stream.write_all(&buf[..n]).await.unwrap();

        if n != 48 {
            debug!("echo lengths don't match {n} != 48");
        }
    });

    let o4_client = proto::Client::from_params(client_config);
    let mut o4c_stream = o4_client.wrap(&mut c).await?;

    o4c_stream.write_all(&(*message)[..]).await?;

    let mut buf = vec![0_u8; message.len()];
    let _ = o4c_stream.read(&mut buf).await?;
    assert_eq!(
        &message[..],
        &buf,
        "{}",
        String::from_utf8(message.to_vec())?
    );

    Ok(())
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_10k_x1() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);

    let mut o4_server = Server::new_from_random();
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = proto::Client::from_params(client_config);
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    tokio::spawn(async move {
        let msg = [0_u8; 10240];
        w.write_all(&msg)
            .await
            .unwrap_or_else(|e| panic!("failed on write {e}"));
    });

    let expected_total = 10240;
    let mut buf = vec![0_u8; 1024 * 11];
    let mut received: usize = 0;
    for i in 0..8 {
        debug!("client read: {i}");
        tokio::select! {
            res = r.read(&mut buf) => {
                let n = res?;
                received += n;
                trace!("received: {n}: total:{received}");
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(1000)) => {
                panic!("client failed to read after {i} iterations: timeout");
            }
        }
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
    Ok(())
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_100M() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);

    let mut o4_server = Server::new_from_random();
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = proto::Client::from_params(client_config);
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    tokio::spawn(async move {
        let msg = [0_u8; 1024];
        for i in 0..1024 * 100 {
            w.write_all(&msg)
                .await
                .unwrap_or_else(|_| panic!("failed on write #{i}"));
        }
    });

    let expected_total = 1024 * 1024 * 100;
    let mut buf = vec![0_u8; 1024 * 100];
    let mut received: usize = 0;
    for i in 0..1024 * 100 {
        // debug!("client read: {i}");
        tokio::select! {
            res = r.read(&mut buf) => {
                received += res?;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(1000)) => {
                panic!("client failed to read after {i} iterations: timeout");
            }
        }
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
    Ok(())
}

#[tokio::test]
async fn transfer_2_x() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);

    let mut o4_server = proto::Server::new_from_random();
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = proto::Client::from_params(client_config);
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    let base: usize = 2;
    tokio::spawn(async move {
        for i in 0..23 {
            let msg = vec![0_u8; base.pow(i)];
            w.write_all(&msg)
                .await
                .unwrap_or_else(|_| panic!("failed on write #{i}"));
        }
    });

    let mut buf = vec![0_u8; 1024 * 100];
    let expected_total: usize = (0..23).map(|i| base.pow(i)).sum();
    let mut received = 0;

    loop {
        let res_timeout = tokio::time::timeout(Duration::from_millis(1000), r.read(&mut buf)).await;

        let res = res_timeout.unwrap();
        let n = res?;
        if n == 0 {
            debug!("read 0?");
            break;
        }

        received += n;
        match received.cmp(&expected_total) {
            Ordering::Less => {}
            Ordering::Equal => break,
            Ordering::Greater => {
                panic!("received more than expected {received} > {expected_total}")
            }
        }
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
    Ok(())
}
