use crate::{
    obfs4::{
        self,
        constants::*,
        handshake::Obfs4NtorPublicKey,
        proto::{Obfs4Stream, IAT},
    },
    Error,
};
use ptrs::{args::Args, FutureResult as F};

use std::{
    marker::PhantomData,
    net::{SocketAddrV4, SocketAddrV6},
    pin::Pin,
    str::FromStr,
    time::Duration,
};

use hex::FromHex;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tracing::trace;

pub type Obfs4PT = Transport<TcpStream>;

#[derive(Debug, Default)]
pub struct Transport<T> {
    _p: PhantomData<T>,
}
impl<T> Transport<T> {
    pub const NAME: &'static str = "obfs4";
}

impl<T> ptrs::PluggableTransport<T> for Transport<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
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
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ServerPT = obfs4::Server;
    type Error = Error;
    type Transport = Transport<T>;

    /// A path where the launched PT can store state.
    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// Pluggable transport attempts to parse and validate options from a string,
    /// typically using ['parse_smethod_args'].
    fn options(&mut self, _opts: &Args) -> Result<&mut Self, Self::Error> {
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

    fn method_name() -> String {
        "obfs4".into()
    }
}

impl<T> ptrs::ClientBuilderByTypeInst<T> for obfs4::ClientBuilder
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ClientPT = obfs4::Client;
    type Error = Error;
    type Transport = Transport<T>;

    /// A path where the launched PT can store state.
    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    /// Pluggable transport attempts to parse and validate options from a string,
    /// typically using ['parse_smethod_args'].
    fn options(&mut self, opts: &Args) -> Result<&mut Self, Self::Error> {
        let server_materials = match opts.retrieve(CERT_ARG) {
            Some(cert_strs) => {
                // The "new" (version >= 0.0.3) bridge lines use a unified "cert" argument
                // for the Node ID and Public Key.
                if cert_strs.is_empty() {
                    return Err(format!("missing argument '{NODE_ID_ARG}'").into());
                }
                trace!("cert string: {}", &cert_strs);
                let ntor_pk = Obfs4NtorPublicKey::from_str(&cert_strs)?;
                let pk: [u8; NODE_PUBKEY_LENGTH] = *ntor_pk.pk.as_bytes();
                let id: [u8; NODE_ID_LENGTH] = ntor_pk.id.as_bytes().try_into().unwrap();
                (pk, id)
            }
            None => {
                // The "old" style (version <= 0.0.2) bridge lines use separate Node ID
                // and Public Key arguments in Base16 encoding and are a UX disaster.
                let node_id_strs = opts
                    .retrieve(NODE_ID_ARG)
                    .ok_or(format!("missing argument '{NODE_ID_ARG}'"))?;
                let id = <[u8; NODE_ID_LENGTH]>::from_hex(node_id_strs)
                    .map_err(|e| format!("malformed node id: {e}"))?;

                let public_key_strs = opts
                    .retrieve(PUBLIC_KEY_ARG)
                    .ok_or(format!("missing argument '{PUBLIC_KEY_ARG}'"))?;

                let pk = <[u8; 32]>::from_hex(public_key_strs)
                    .map_err(|e| format!("malformed public key: {e}"))?;
                // Obfs4NtorPublicKey::new(pk, node_id)
                (pk, id)
            }
        };

        // IAT config is common across the two bridge line formats.
        let iat_strs = opts
            .retrieve(IAT_ARG)
            .ok_or(format!("missing argument '{IAT_ARG}'"))?;
        let iat_mode = IAT::from_str(&iat_strs)?;

        self.with_node_pubkey(server_materials.0)
            .with_node_id(server_materials.1)
            .with_iat_mode(iat_mode);

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

    fn method_name() -> String {
        "obfs4".into()
    }
}

/// Example wrapping transport that just passes the incoming connection future through
/// unmodified as a proof of concept.
impl<InRW, InErr> ptrs::ClientTransport<InRW, InErr> for obfs4::Client
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
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

    fn method_name() -> String {
        "obfs4".into()
    }
}

impl<InRW> ptrs::ServerTransport<InRW> for obfs4::Server
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type OutRW = Obfs4Stream<InRW>;
    type OutErr = Error;
    type Builder = obfs4::ServerBuilder;

    /// Use something that can be accessed reference (Arc, Rc, etc.)
    fn reveal(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(obfs4::Server::wrap(self, io))
    }

    fn method_name() -> String {
        "obfs4".into()
    }
}

#[cfg(test)]
mod test {}
