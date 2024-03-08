// #![feature(associated_type_defaults)]

use futures::Future; // , Sink, TryStream};

mod helpers;
pub use helpers::*;

/// Future containing a generic result. We use this for functions that take
/// and/or return futures that will produce Read/Write tunnels once awaited.
pub type F<T, E> = Box<dyn Future<Output = Result<T, E>> + Send>;

pub struct Passthrough;

pub mod client {
    use std::pin::Pin;
    use std::time::{Duration, Instant};

    use futures::Future; // , Sink, TryStream};

    use super::{Passthrough, F};

    /// Client Transport trait1
    pub trait T1<InRW, InErr> {
        type OutRW;
        type OutErr: std::error::Error;

        fn wrap(&self, input: Pin<F<InRW, InErr>>) -> Pin<F<Self::OutRW, Self::OutErr>>;
    }

    /// Example wrapping transport that just passes the incoming connection future through
    /// unmodified as a proof of concept.
    impl<InRW, InErr: std::error::Error> T1<InRW, InErr> for Passthrough {
        type OutRW = InRW;
        type OutErr = InErr;

        fn wrap(&self, input: Pin<F<InRW, InErr>>) -> Pin<F<Self::OutRW, Self::OutErr>> {
            input
        }
    }

    /// Creator1 defines a stream creator that could be applied to either the input
    /// stream feature or the resulting stream future making them composable.
    pub trait C1 {
        type OutRW;
        type OutErr;
        type Future: Future<Output = Result<Self::OutRW, Self::OutErr>>;

        fn new() -> Self::Future;
    }

    /// In concept this trait provides extended functionality that can be appled to
    /// the client / server traits for creating connections / pluggable transports.
    /// this is still in a TODO state.
    pub trait ConnectExt: C1 {
        fn connect_with_deadline(
            &mut self,
            deadline: Instant,
        ) -> Result<Self::Future, tokio::time::error::Elapsed>;
        fn connect_with_timeout(
            &mut self,
            timeout: Duration,
        ) -> Result<Self::Future, tokio::time::error::Elapsed>;
    }

    impl C1 for tokio::net::TcpStream {
        type OutRW = Self;
        type OutErr = std::io::Error;
        type Future = Pin<F<Self::OutRW, Self::OutErr>>;

        fn new() -> Self::Future {
            let f = tokio::net::TcpStream::connect("127.0.0.1:9000");
            Box::pin(f)
        }
    }

    impl C1 for tokio::net::UdpSocket {
        type OutErr = std::io::Error;
        type OutRW = tokio::net::UdpSocket;
        type Future = Pin<F<Self::OutRW, Self::OutErr>>;

        fn new() -> Self::Future {
            let f = tokio::net::UdpSocket::bind("127.0.0.1:9000");
            Box::pin(f)
        }
    }
}

pub mod server {
    use std::pin::Pin;

    use super::{Passthrough, F};

    /// Server Transport trait2 - try using futures instead of actual objects
    // This doesn't work because it requires the listener object that was used
    // to create the `input` Future must live for `'static` for the future to
    // be valid, but that can't be guaranteed and is difficult to work with.
    pub trait T2<InRW, InErr> {
        type OutRW;
        type OutErr: std::error::Error;

        fn wrap_acc(&self, input: Pin<F<InRW, InErr>>) -> Pin<F<Self::OutRW, Self::OutErr>>;
    }

    impl<I, E: std::error::Error> T2<I, E> for Passthrough {
        type OutRW = I;
        type OutErr = E;

        fn wrap_acc(&self, input: Pin<F<I, E>>) -> Pin<F<Self::OutRW, Self::OutErr>> {
            input
        }
    }

    /// Server Transport trait1 - try using objects so we can accept and then
    /// handshake (proxy equivalent of accept) as separate steps by the transport
    /// user.
    pub trait T1<RW> {
        type OutRW;
        type OutErr: std::error::Error;

        fn wrap_new(&self, io: RW) -> Pin<F<Self::OutRW, Self::OutErr>>;
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
    impl<RW: Send + 'static> T1<RW> for Passthrough {
        type OutRW = RW;
        type OutErr = std::io::Error;

        fn wrap_new(&self, io: RW) -> Pin<F<Self::OutRW, Self::OutErr>> {
            Box::pin(Self::hs(io))
        }
    }

    impl Passthrough {
        async fn hs<RW>(io: RW) -> Result<RW, std::io::Error> {
            Ok(io)
        }
    }
}

#[cfg(test)]
mod tests {

    use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};
    use tracing::info;
    use tracing_subscriber::filter::LevelFilter;

    use std::env;
    use std::str::FromStr;
    use std::sync::Once;
    use std::time::Duration;

    use super::client::{C1 as _, T1 as _};
    use super::server::T1 as _;
    use super::*;

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

    #[tokio::test]
    async fn passthrough_wrap_client() -> Result<(), std::io::Error> {
        init_subscriber();

        let p = Passthrough {};

        // note that this is not await-ed here so it is not executed until later
        let tcp_dial_fut = TcpStream::new();

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
        let conn_fut = p.wrap(tcp_dial_fut);

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

            let mut sock = sp.wrap_new(conn).await.unwrap();
            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        tokio::time::sleep(Duration::from_secs(1)).await;
        info!("wrapping client fut");

        // this takes the dial future and creates a new future
        let conn_fut = p.wrap(tcp_dial_fut);

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
        let conn_fut1 = p.wrap(tcp_dial_fut);
        let conn_fut2 = p.wrap(conn_fut1);
        let conn_fut3 = p.wrap(conn_fut2);
        let mut conn = conn_fut3.await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;

        Ok(())
    }
}
