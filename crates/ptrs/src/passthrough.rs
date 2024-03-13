use tokio::io::{AsyncRead, AsyncWrite};

use super::*;

pub struct Passthrough {}

impl<T> PluggableTransport<T> for Passthrough
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    type ClientBuilder = BuilderC;
    type ServerBuilder = BuilderS;
    // type Client = Passthrough;
    // type Server = Passthrough;

    fn name() -> String {
        "passthrough".into()
    }

    // fn client_builder() -> <<Self as PluggableTransport<T,std::io::Error>>::Client as ClientTransport<T, std::io::Error>>::Builder {
    fn client_builder() -> <Self as PluggableTransport<T>>::ClientBuilder {
        BuilderC::default()
    }

    // fn server_builder() -> <<Self as PluggableTransport<T, std::io::Error>>::Server as ServerTransport<T>>::Builder{
    fn server_builder() -> <Self as PluggableTransport<T>>::ServerBuilder {
        BuilderS::default()
    }
}

#[derive(Debug, Default)]
pub struct BuilderS {}

impl ServerBuilder for BuilderS {
    type Error = std::io::Error;
    type ServerPT = Passthrough;
    type Transport = Passthrough;

    /// A path where the launched PT can store state.
    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// Pluggable transport attempts to parse and validate options from a string,
    /// typically using ['parse_smethod_args'].
    fn options(&mut self, _opts: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// The maximum time we should wait for a pluggable transport binary to
    /// report successful initialization. If `None`, a default value is used.
    fn timeout(&mut self, _timeout: Option<Duration>) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// An IPv4 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v4_bind_addr(&mut self, _addr: SocketAddrV4) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// An IPv6 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v6_bind_addr(&mut self, _addr: SocketAddrV6) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// Builds a new PtCommonParameters.
    ///
    /// **Errors**
    /// If a required field has not been initialized.
    fn build(&self) -> Self::ServerPT {
        Passthrough {}
    }
}

#[derive(Debug, Default)]
pub struct BuilderC {}

impl<T> ClientBuilderByTypeInst<T> for BuilderC
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    type ClientPT = Passthrough;
    type Error = std::io::Error;
    type Transport = Passthrough;

    /// A path where the launched PT can store state.
    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// Pluggable transport attempts to parse and validate options from a string,
    /// typically using ['parse_smethod_args'].
    fn options(&mut self, _opts: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// The maximum time we should wait for a pluggable transport binary to
    /// report successful initialization. If `None`, a default value is used.
    fn timeout(&mut self, _timeout: Option<Duration>) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// An IPv4 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v4_bind_addr(&mut self, _addr: SocketAddrV4) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// An IPv6 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v6_bind_addr(&mut self, _addr: SocketAddrV6) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// Builds a new PtCommonParameters.
    ///
    /// **Errors**
    /// If a required field has not been initialized.
    fn build(&self) -> Self::ClientPT {
        Passthrough {}
    }
}

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
    type Builder = BuilderC;

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
    type Builder = BuilderS;

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
mod design_tests {

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use tracing::info;
    use tracing_subscriber::filter::LevelFilter;

    use std::env;
    use std::pin::Pin;
    use std::str::FromStr;
    use std::sync::Once;
    use std::time::Duration;

    use super::Passthrough;
    use crate::{
        ClientBuilderByTypeInst,
        ClientTransport,
        FutureResult,
        PluggableTransport,
        ServerBuilder, // ClientInfo, Conn,
        ServerTransport,
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

    async fn establish_using_pt<T, E, P>(
        t_fut: Pin<FutureResult<T, E>>,
    ) -> Result<
        Pin<
            FutureResult<
                <<<P as PluggableTransport<T>>::ClientBuilder as ClientBuilderByTypeInst<T>>::ClientPT as ClientTransport<T,E>>::OutRW,
                <<<P as PluggableTransport<T>>::ClientBuilder as ClientBuilderByTypeInst<T>>::ClientPT as ClientTransport<T,E>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error>,
    >
    where
        P: PluggableTransport<T>,
        P::ClientBuilder: ClientBuilderByTypeInst<T>,
        <<P as PluggableTransport<T>>::ClientBuilder as ClientBuilderByTypeInst<T>>::ClientPT: ClientTransport<T,E>,
        <<P as PluggableTransport<T>>::ClientBuilder as ClientBuilderByTypeInst<T>>::Error: std::error::Error + 'static,
        E: std::error::Error + 'static,
    {
        Ok(P::client_builder()
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?
            .build()
            .establish(t_fut))
    }

    #[tokio::test]
    async fn client_interface_establish_pt() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (mut sock, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        let _ = rx.await.unwrap();

        let tcp_fut = TcpStream::connect("127.0.0.1:8000");

        // let builder = <Passthrough as PluggableTransport<TcpStream>>::ClientBuilder::default();
        // let builder = <<Passthrough as PluggableTransport<TcpStream, std::io::Error>>::Client as ClientTransport<TcpStream,std::io::Error>>::Builder::default();

        let conn_fut =
            establish_using_pt::<TcpStream, std::io::Error, Passthrough>(Box::pin(tcp_fut))
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

        info!("connecting to tcp and pt");
        let mut conn = conn_fut.await?;

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

    async fn establish_using_builder<T, E, B>(
        t_fut: Pin<FutureResult<T, E>>,
        mut pt: B,
    ) -> Result<
        Pin<
            FutureResult<
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
            .establish(t_fut))
    }

    #[tokio::test]
    async fn client_interface_establish() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (mut sock, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        let _ = rx.await.unwrap();

        let tcp_fut = TcpStream::connect("127.0.0.1:8000");

        // let builder = <Passthrough as PluggableTransport<TcpStream>>::ClientBuilder::default();
        // let builder = <<Passthrough as PluggableTransport<TcpStream, std::io::Error>>::Client as ClientTransport<TcpStream,std::io::Error>>::Builder::default();
        let builder = <Passthrough as PluggableTransport<TcpStream>>::client_builder();

        let conn_fut = establish_using_builder(Box::pin(tcp_fut), builder)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

        info!("connecting to tcp and pt");
        let mut conn = conn_fut.await?;

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

    async fn wrap_using_pt<T, E, P>(
        t: T,
    ) -> Result<
        Pin<
            FutureResult<
                <<<P as PluggableTransport<T>>::ClientBuilder as ClientBuilderByTypeInst<T>>::ClientPT as ClientTransport<T,E>>::OutRW,
                <<<P as PluggableTransport<T>>::ClientBuilder as ClientBuilderByTypeInst<T>>::ClientPT as ClientTransport<T,E>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error>,
    >
    where
        P: PluggableTransport<T>,
        P::ClientBuilder: ClientBuilderByTypeInst<T>,
        <<P as PluggableTransport<T>>::ClientBuilder as ClientBuilderByTypeInst<T>>::ClientPT: ClientTransport<T,E>,
        <<P as PluggableTransport<T>>::ClientBuilder as ClientBuilderByTypeInst<T>>::Error: std::error::Error + 'static,
        E: std::error::Error + 'static,
    {
        Ok(P::client_builder()
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?
            .build()
            .wrap(t))
    }

    #[tokio::test]
    async fn client_interface_wrap_pt() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (mut sock, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        let _ = rx.await.unwrap();

        info!("connecting to tcp");
        let tcp_conn = TcpStream::connect("127.0.0.1:8000").await?;

        info!("connecting to pt over tcp");
        let conn_fut = wrap_using_pt::<TcpStream, std::io::Error, Passthrough>(tcp_conn)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

        let mut conn = conn_fut.await?;

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

    async fn wrap_conn_in_builder<T, E, B>(
        t: T,
        mut pt: B,
    ) -> Result<
        Pin<
            FutureResult<
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
    async fn client_interface_wrap() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (mut sock, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        let _ = rx.await.unwrap();

        info!("connecting to tcp");
        let tcp_conn = TcpStream::connect("127.0.0.1:8000").await?;

        let builder = <Passthrough as PluggableTransport<TcpStream>>::client_builder();

        let mut conn = wrap_conn_in_builder(tcp_conn, builder)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?
            .await?;

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


    async fn wrap_server_using_pt<T, E, P>(
        t: T,
    ) -> Result<
        Pin<
            FutureResult<
                <<<P as PluggableTransport<T>>::ServerBuilder as ServerBuilder>::ServerPT as ServerTransport<T>>::OutRW,
                <<<P as PluggableTransport<T>>::ServerBuilder as ServerBuilder>::ServerPT as ServerTransport<T>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error>,
    >
    where
        P: PluggableTransport<T>,
        P::ClientBuilder: ClientBuilderByTypeInst<T>,
        <<P as PluggableTransport<T>>::ServerBuilder as ServerBuilder>::ServerPT: ServerTransport<T>,
        <<P as PluggableTransport<T>>::ServerBuilder as ServerBuilder>::Error: std::error::Error + 'static,
        E: std::error::Error + 'static,
    {
        Ok(P::server_builder()
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?
            .build()
            .reveal(t))
    }

    #[tokio::test]
    async fn server_interface_wrap_pt() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (tcp_conn, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let conn_fut = wrap_server_using_pt::<TcpStream, std::io::Error, Passthrough>(tcp_conn)
                .await
                .unwrap();
            let mut conn = conn_fut.await.unwrap();
            info!("pt accepted connection");

            let (mut r, mut w) = tokio::io::split(&mut conn);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        let _ = rx.await.unwrap();

        info!("connecting to tcp");
        let tcp_conn = TcpStream::connect("127.0.0.1:8000").await?;

        info!("connecting to pt over tcp");
        let conn_fut = wrap_using_pt::<TcpStream, std::io::Error, Passthrough>(tcp_conn)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

        let mut conn = conn_fut.await?;

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

    async fn wrap_server_in_builder<T, B>(
        t: T,
        mut pt_builder: B,
    ) -> Result<
        Pin<
            FutureResult<
                <<B as ServerBuilder>::ServerPT as ServerTransport<T>>::OutRW,
                <<B as ServerBuilder>::ServerPT as ServerTransport<T>>::OutErr,
            >,
        >,
        Box<dyn std::error::Error>,
    >
    where
        B: ServerBuilder,
        B::ServerPT: ServerTransport<T>,
        B::Error: std::error::Error + 'static,
    {
        Ok(pt_builder
            .statefile_location("./")?
            .timeout(Some(Duration::from_secs(30)))?
            .build()
            .reveal(t))
    }

    #[tokio::test]
    async fn server_interface_wrap() -> Result<(), std::io::Error> {
        init_subscriber();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
                .await
                .unwrap();
            info!("tcp listening");
            // ensure / force listener to be ready before connect.
            tx.send(()).unwrap();

            let (tcp_conn, _) = listener.accept().await.unwrap();
            info!("tcp accepted");

            let builder = <Passthrough as PluggableTransport<TcpStream>>::server_builder();

            let mut conn = wrap_server_in_builder(tcp_conn, builder)
                .await
                .unwrap()
                .await
                .unwrap();

            let (mut r, mut w) = tokio::io::split(&mut conn);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // ensure / force listener to be ready before connect.
        let _ = rx.await.unwrap();

        info!("connecting to tcp");
        let mut conn = TcpStream::connect("127.0.0.1:8000").await?;

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
    async fn basic_wrap_client() -> Result<(), std::io::Error> {
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

    #[tokio::test]
    async fn basic_wrap_server() -> Result<(), std::io::Error> {
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
    async fn server_composition() -> Result<(), std::io::Error> {
        init_subscriber();

        let p = Passthrough {};
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:9003")
                .await
                .unwrap();
            tx.send(()).unwrap();

            let (tcp_sock, _) = listener.accept().await.unwrap();

            let conn1 = p.reveal(tcp_sock).await.unwrap();
            let conn2 = p.reveal(conn1).await.unwrap();
            let mut sock = p.reveal(conn2).await.unwrap();

            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let _ = rx.await.unwrap();
        let mut conn = Box::pin(TcpStream::connect("127.0.0.1:9003")).await?;

        let msg = b"a man a plan a canal panama";
        _ = conn.write(&msg[..]).await?;

        let mut buf = [0u8; 27];
        _ = conn.read(&mut buf).await?;

        Ok(())
    }

    #[tokio::test]
    async fn client_composition() -> Result<(), std::io::Error> {
        init_subscriber();

        let p = Passthrough {};
        let tcp_dial_fut = Box::pin(TcpStream::connect("127.0.0.1:9002"));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:9002")
                .await
                .unwrap();
            tx.send(()).unwrap();
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = tokio::io::split(&mut sock);
            _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let _ = rx.await.unwrap();
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
