use tokio::io::{AsyncRead, AsyncWrite};

use super::*;

pub struct Passthrough {}

impl<I, E: std::error::Error> ServerTransport2<I, E> for Passthrough {
    type OutRW = I;
    type OutErr = E;

    fn wrap_acc(&self, input: Pin<F<I, E>>) -> Pin<F<Self::OutRW, Self::OutErr>> {
        input
    }
}

/// Example wrapping transport that just passes the incoming connection future through
/// unmodified as a proof of concept.
impl<InRW> ClientTransport<InRW, std::io::Error> for Passthrough
where
    InRW: AsyncRead + AsyncWrite + Send + 'static,
{
    type OutRW = InRW;
    type OutErr = std::io::Error;

    fn establish(&self, input: Pin<F<InRW, std::io::Error>>) -> Pin<F<Self::OutRW, Self::OutErr>> {
        input
    }

    fn wrap(&self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(Self::hs(io))
    }
}

// -_-    must be static, even though I wish it didn't
//
// the parameter type `RW` may not live long enough
// help: consider adding an explicit lifetime bound
//     |
// 125 |     impl<RW: 'static> T1<RW> for Passthrough {
//     |            +++++++++
//
//
impl<RW: Send + 'static> ServerTransport<RW> for Passthrough {
    type OutRW = RW;
    type OutErr = std::io::Error;

    fn reveal(&self, io: RW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(Self::hs(io))
    }
}

impl Passthrough {
    async fn hs<RW>(io: RW) -> Result<RW, std::io::Error> {
        Ok(io)
    }
}

#[cfg(test)]
mod tests {

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use tracing::info;
    use tracing_subscriber::filter::LevelFilter;

    use std::env;
    use std::str::FromStr;
    use std::sync::Once;
    use std::time::Duration;

    use super::Passthrough;
    use crate::{
        ClientBuilderByTypeInst,
        ClientTransport,
        PluggableTransportFut,
        // ServerTransport as _, ClientInfo, Conn,
    };

    #[allow(unused)]
    fn print_type_of<T>(_: &T) {
        info!("{}", std::any::type_name::<T>())
    }

    static SUBSCRIBER_INIT: Once = Once::new();

    pub fn init_subscriber() {
        SUBSCRIBER_INIT.call_once(|| {
            let level = env::var("RUST_LOG_LEVEL").unwrap_or("error".into());
            let lf = LevelFilter::from_str(&level).unwrap();

            tracing_subscriber::fmt().with_max_level(lf).init();
        });
    }

    async fn establish<T, E, B>(
        t: T,
        mut pt: B,
    ) -> Result<
        std::pin::Pin<
            PluggableTransportFut<
                <<B as ClientBuilderByTypeInst<T>>::ClientPT as ClientTransport<T, E>>::OutRW,
                <<B as ClientBuilderByTypeInst<T>>::ClientPT as ClientTransport<T, E>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error>,
    >
    where
        B: ClientBuilderByTypeInst<T>,
        B::ClientPT: ClientTransport<T, E>,
        B::Error: std::error::Error + 'static,
    {
        Ok(pt
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?
            .build()
            .wrap(t))
    }

    #[tokio::test]
    async fn test_interface() -> Result<(), std::io::Error> {
        init_subscriber();
        let t_fut = TcpStream::connect("127.0.0.1:8080");

        let builder = Passthrough::ClientBuilder::default();

        let conn = establish(t_fut, builder).await?;

        Ok(())
    }

    #[tokio::test]
    async fn passthrough_wrap_client() -> Result<(), std::io::Error> {
        init_subscriber();

        let p = Passthrough {};

        // note that this is not await-ed here so it is not executed until later
        let tcp_dial_fut = TcpStream::connect("127.0.0.1:9000");

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:9000")
                .await
                .unwrap();
            info!("tcp listening");

            let (mut sock, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        tokio::time::sleep(Duration::from_secs(1)).await;
        info!("wrapping client fut");

        // this takes the dial future and creates a new future
        let conn_fut = p.establish(Box::pin(tcp_dial_fut));

        info!("running client fut");
        // once the connection future is await-ed it will await the dial future.
        let mut conn = conn_fut.await?;
        info!("client connected");

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;
        info!(
            "server echoed: \"{}\"",
            String::from_utf8(buf.to_vec()).unwrap()
        );

        Ok(())
    }

    // Other maybe good constructions?
    // TcpStream::new().wrap(p).await?;
    //

    #[tokio::test]
    async fn passthrough_wrap_server() -> Result<(), std::io::Error> {
        init_subscriber();

        let p = Passthrough {};

        // note that this is not await-ed here so it is not executed until later
        let tcp_dial_fut = Box::pin(TcpStream::connect("127.0.0.1:9001"));

        tokio::spawn(async move {
            let sp = Passthrough {};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:9001")
                .await
                .unwrap();
            info!("tcp listening");

            // let (mut sock, _) = sp.wrap_acc(Box::pin(listener.accept())).await.unwrap();
            let (conn, _) = listener.accept().await.unwrap();
            info!("tcp accepted, and handshaked");

            let mut sock = sp.wrap(conn).await.unwrap();
            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        tokio::time::sleep(Duration::from_secs(1)).await;
        info!("wrapping client fut");

        // this takes the dial future and creates a new future
        let conn_fut = p.establish(tcp_dial_fut);

        info!("running client fut");
        // once the connection future is await-ed it will await the dial future.
        let mut conn = conn_fut.await?;
        info!("client connected");

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;
        info!(
            "server echoed: \"{}\"",
            String::from_utf8(buf.to_vec()).unwrap()
        );

        Ok(())
    }

    #[tokio::test]
    async fn passthrough_composition_client() -> Result<(), std::io::Error> {
        init_subscriber();

        let p = Passthrough {};
        let tcp_dial_fut = Box::pin(TcpStream::connect("127.0.0.1:9002"));

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:9002")
                .await
                .unwrap();
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        tokio::time::sleep(Duration::from_secs(1)).await;
        let conn_fut1 = p.establish(Box::pin(tcp_dial_fut));
        let conn_fut2 = p.establish(Box::pin(conn_fut1));
        let conn_fut3 = p.establish(Box::pin(conn_fut2));
        let mut conn = conn_fut3.await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;

        Ok(())
    }
}
