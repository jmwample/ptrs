use crate::{
    obfs4::{self, proto::Obfs4Stream},
    Error,
};
use ptrs::FutureResult as F;

use std::{
    net::{SocketAddrV4, SocketAddrV6},
    pin::Pin,
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Default)]
pub struct Transport {}
impl Transport {
    pub const NAME: &'static str = "obfs4";
}

impl<T> ptrs::PluggableTransport<T> for Transport
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type ClientBuilder = obfs4::ClientBuilder;
    type ServerBuilder = obfs4::ServerBuilder;

    fn name() -> String {
        "obfs4".into()
    }

    fn client_builder() -> <Self as ptrs::PluggableTransport<T>>::ClientBuilder {
        obfs4::ClientBuilder::default()
    }

    fn server_builder() -> <Self as ptrs::PluggableTransport<T>>::ServerBuilder {
        obfs4::ServerBuilder::default()
    }
}

impl<T> ptrs::ServerBuilder<T> for obfs4::ServerBuilder
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type ServerPT = obfs4::Server;
    type Error = Error;
    type Transport = Transport;

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
        obfs4::ServerBuilder::build(self)
    }
}

impl<T> ptrs::ClientBuilderByTypeInst<T> for obfs4::ClientBuilder
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type ClientPT = obfs4::Client;
    type Error = Error;
    type Transport = Transport;

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
        obfs4::ClientBuilder::build(self)
    }
}

/// Example wrapping transport that just passes the incoming connection future through
/// unmodified as a proof of concept.
impl<InRW, InErr> ptrs::ClientTransport<InRW, InErr> for obfs4::Client
where
    InRW: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    InErr: std::error::Error + Send + Sync + 'static,
{
    type OutRW = Obfs4Stream<InRW>;
    type OutErr = Error;
    type Builder = obfs4::ClientBuilder;

    fn establish(self, input: Pin<F<InRW, InErr>>) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(obfs4::Client::establish(self, input))
    }

    fn wrap(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(obfs4::Client::wrap(self, io))
    }
}

impl<InRW> ptrs::ServerTransport<InRW> for obfs4::Server
where
    InRW: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type OutRW = Obfs4Stream<InRW>;
    type OutErr = Error;
    type Builder = obfs4::ServerBuilder;

    fn reveal(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(obfs4::Server::wrap(self, io))
    }
}

#[cfg(test)]
mod test {}
