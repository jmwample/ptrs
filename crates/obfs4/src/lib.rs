#![doc = include_str!("../../../doc/crate.md")]

// #![feature(trait_alias)]

// #![allow(dead_code)]
// #![allow(warnings)]

pub mod obfs4;

pub mod common;
pub mod stream;
pub mod traits;
pub mod tunnel_mgr;

mod pt;
pub use pt::{Obfs4PT, Transport};

mod error;
pub use error::{Error, Result};

pub const OBFS4_NAME: &str = "obfs4";

#[cfg(test)]
pub(crate) mod test_utils;

#[cfg(debug_assertions)]
pub mod dev {
    /// Pre-generated / shared key for use while running in debug mode.
    pub const DEV_PRIV_KEY: &[u8; 32] = b"0123456789abcdeffedcba9876543210";

    /// Client obfs4 arguments based on pre-generated dev key `DEV_PRIV_KEY`.
    pub const CLIENT_ARGS: &str =
        "cert=AAAAAAAAAAAAAAAAAAAAAAAAAADTSFvsGKxNFPBcGdOCBSgpEtJInG9zCYZezBPVBuBWag;iat-mode=0";

    /// Server obfs4 arguments based on pre-generated dev key `DEV_PRIV_KEY`.
    pub const SERVER_ARGS: &str = "drbg-seed=0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f;node-id=0000000000000000000000000000000000000000;private-key=3031323334353637383961626364656666656463626139383736353433323130;iat-mode=0";

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::common::curve25519::StaticSecret;
        use crate::obfs4::constants::*;
        use crate::obfs4::handshake::Obfs4NtorSecretKey;
        use crate::obfs4::{ClientBuilder, ServerBuilder};
        use ptrs::ServerBuilder as _;

        use ptrs::args::Args;
        use tokio::net::TcpStream;
        use tor_llcrypto::pk::rsa::RsaIdentity;
        use tracing::trace;

        pub fn trace_print_dev_args() {
            let static_secret = StaticSecret::from(*DEV_PRIV_KEY);
            let sk =
                Obfs4NtorSecretKey::new(static_secret, RsaIdentity::from([0u8; NODE_ID_LENGTH]));
            let mut client_args = Args::new();
            client_args.insert(CERT_ARG.into(), vec![sk.pk.to_string()]);
            client_args.insert(IAT_ARG.into(), vec!["0".into()]);
            trace!("{}", client_args.encode_smethod_args());
        }

        #[test]
        fn test_parse() {
            trace_print_dev_args();

            let args = Args::parse_client_parameters(CLIENT_ARGS).unwrap();
            let mut builder = ClientBuilder::default();
            <ClientBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut builder, &args)
                .unwrap();

            let server_params = Args::parse_client_parameters(SERVER_ARGS).unwrap();
            let mut server_builder = ServerBuilder::<TcpStream>::default();
            server_builder.options(&server_params).unwrap();
        }
    }
}
