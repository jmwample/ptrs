use crate::{
    common::{drbg, elligator2, ntor},
    obfs4::framing,
};

use std::time::Duration;

//=========================[Framing/Msgs]=====================================//

/// Maximum handshake size including padding
pub const MAX_HANDSHAKE_LENGTH: usize = 8192;

pub const SHA256_SIZE: usize = 32;
pub const MARK_LENGTH: usize = SHA256_SIZE / 2;
pub const MAC_LENGTH: usize = SHA256_SIZE / 2;

/// Minimum padding allowed in a client handshake message
pub const CLIENT_MIN_PAD_LENGTH: usize =
    (SERVER_MIN_HANDSHAKE_LENGTH + INLINE_SEED_FRAME_LENGTH) - CLIENT_MIN_HANDSHAKE_LENGTH;
pub const CLIENT_MAX_PAD_LENGTH: usize = MAX_HANDSHAKE_LENGTH - CLIENT_MIN_HANDSHAKE_LENGTH;
pub const CLIENT_MIN_HANDSHAKE_LENGTH: usize =
    elligator2::REPRESENTATIVE_LENGTH + MARK_LENGTH + MAC_LENGTH;

pub const SERVER_MIN_PAD_LENGTH: usize = 0;
pub const SERVER_MAX_PAD_LENGTH: usize =
    MAX_HANDSHAKE_LENGTH - (SERVER_MIN_HANDSHAKE_LENGTH + INLINE_SEED_FRAME_LENGTH);
pub const SERVER_MIN_HANDSHAKE_LENGTH: usize =
    elligator2::REPRESENTATIVE_LENGTH + ntor::AUTH_LENGTH + MARK_LENGTH + MAC_LENGTH;

pub const INLINE_SEED_FRAME_LENGTH: usize =
    framing::FRAME_OVERHEAD + PACKET_OVERHEAD + SEED_PACKET_PAYLOAD_LENGTH;

pub const PACKET_OVERHEAD: usize = 2 + 1;
pub const MAX_PACKET_PAYLOAD_LENGTH: usize = framing::MAX_FRAME_PAYLOAD_LENGTH - PACKET_OVERHEAD;
pub const MAX_PACKET_PADDING_LENGTH: usize = MAX_PACKET_PAYLOAD_LENGTH;
pub const SEED_PACKET_PAYLOAD_LENGTH: usize = drbg::SEED_LENGTH;

pub const CONSUME_READ_SIZE: usize = framing::MAX_SEGMENT_LENGTH * 16;

//===============================[Proto]======================================//

pub const TRANSPORT_NAME: &str = "obfs4";

pub const NODE_ID_ARG: &str = "node-id";
pub const PUBLIC_KEY_ARG: &str = "public-key";
pub const PRIVATE_KEY_ARG: &str = "private-key";
pub const SEED_ARG: &str = "drbg-seed";
pub const IAT_ARG: &str = "iat-mode";
pub const CERT_ARG: &str = "cert";

pub const BIAS_CMD_ARG: &str = "obfs4-distBias";

pub const REPLAY_TTL: Duration = Duration::from_secs(60);
#[cfg(test)]
pub const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
pub const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(not(test))]
pub const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(not(test))]
pub const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

pub const MAX_IAT_DELAY: usize = 100;
pub const MAX_CLOSE_DELAY: usize = 60;
pub const MAX_CLOSE_DELAY_BYTES: usize = MAX_HANDSHAKE_LENGTH;

pub const SEED_LENGTH: usize = drbg::SEED_LENGTH;
pub const HEADER_LENGTH: usize = framing::FRAME_OVERHEAD + framing::PACKET_OVERHEAD;

pub const SESSION_ID_LEN: usize = 8;