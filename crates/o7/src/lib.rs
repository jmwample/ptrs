#![doc = include_str!("../README.md")]

// use tokio_util::udp::UdpFramed;
use std::marker::PhantomData;
use tokio::net::UdpSocket;

/// o7 Transport base name
pub const OBFS4_NAME: &str = "o7";

/// Transport object implementing ['ptrs::ClientTransport'] for ['tokio::UdpStream']
#[allow(non_camel_case_types)]
pub type o7PT = Transport<UdpSocket>;

/// Central Transport object implementing ['ptrs::ClientTransport']
#[derive(Debug, Default)]
pub struct Transport<T> {
    _p: PhantomData<T>,
}
impl<T> Transport<T> {
    pub const NAME: &'static str = OBFS4_NAME;
}
