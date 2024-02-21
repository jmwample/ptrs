
use crate::{
    Result,
    common::{
        curve25519::{PublicRepresentative, PublicKey},
        HmacSha256,
    },
    obfs4::{
        constants::*, handshake::{AUTHCODE_LENGTH, Authcode, get_epoch_hour, make_pad},
    },
};

use bytes::BufMut;
use hmac::Mac;
use rand::Rng;
use tracing::trace;

// -----------------------------[ Server ]-----------------------------


pub struct ServerHandshakeMessage {
    server_auth: [u8; AUTHCODE_LENGTH],
    pad_len: usize,
    repres: PublicRepresentative,
    pubkey: Option<PublicKey>,
    epoch_hour: String,
}

impl ServerHandshakeMessage {
    pub fn new(repres: PublicRepresentative, server_auth: [u8; AUTHCODE_LENGTH], epoch_hr: String) -> Self {
        Self {
            server_auth,
            pad_len: rand::thread_rng().gen_range(SERVER_MIN_PAD_LENGTH..SERVER_MAX_PAD_LENGTH),
            repres,
            pubkey: None,
            epoch_hour: epoch_hr,
        }
    }

    pub fn server_pubkey(&mut self) -> PublicKey {
        match self.pubkey {
            Some(pk) => pk,
            None => {
                let pk = PublicKey::from(&self.repres);
                self.pubkey = Some(pk);
                pk
            }
        }
    }

    pub fn server_auth(self) -> Authcode {
        self.server_auth
    }

    pub fn marshall(&mut self, buf: &mut impl BufMut, mut h: HmacSha256) -> Result<()> {
        trace!("serializing server handshake");

        h.reset();
        h.update(self.repres.as_bytes().as_ref());
        let mark: &[u8] = &h.finalize_reset().into_bytes()[..MARK_LENGTH];

        // The server handshake is Y | AUTH | P_S | M_S | MAC(Y | AUTH | P_S | M_S | E) where:
        //  * Y is the server's ephemeral Curve25519 public key representative.
        //  * AUTH is the ntor handshake AUTH value.
        //  * P_S is [serverMinPadLength,serverMaxPadLength] bytes of random padding.
        //  * M_S is HMAC-SHA256-128(serverIdentity | NodeID, Y)
        //  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, Y .... E)
        //  * E is the string representation of the number of hours since the UNIX
        //    epoch.

        // Generate the padding
        let pad: &[u8] = &make_pad(self.pad_len)?;

        // Write Y, AUTH, P_S, M_S.
        let mut params = vec![];
        params.extend_from_slice(self.repres.as_bytes());
        params.extend_from_slice(&self.server_auth);
        params.extend_from_slice(pad);
        params.extend_from_slice(mark);
        buf.put(params.as_slice());

        // Calculate and write MAC
        h.update(&params);
        h.update(self.epoch_hour.as_bytes());
        buf.put(&h.finalize_reset().into_bytes()[..MAC_LENGTH]);

        Ok(())
    }
}



// -----------------------------[ Client ]-----------------------------


/// Preliminary message sent in an obfs4 handshake attempting to open a
/// connection from a client to a potential server.
pub struct ClientHandshakeMessage {
    pub(crate) pad_len: usize,
    pub(crate) repres: PublicRepresentative,
    pub(crate) pubkey: Option<PublicKey>,

    // only used when parsing (i.e. on the server side)
    pub(crate) epoch_hour: String,
}

impl ClientHandshakeMessage {
    pub fn new(
        repres: PublicRepresentative,
        pad_len: usize,
        epoch_hour: String,
    ) -> Self {
        Self {
            pad_len,
            repres,
            pubkey: None,

            // only used when parsing (i.e. on the server side)
            epoch_hour,
        }
    }

    pub fn get_public(&mut self) -> PublicKey {
        match self.pubkey {
            Some(pk) => pk,
            None => {
                let pk = PublicKey::from(&self.repres);
                self.pubkey = Some(pk);
                pk
            }
        }
    }

    #[allow(unused)]
    /// Return the elligator2 representative of the public key value.
    pub fn get_representative(&self) -> PublicRepresentative {
        self.repres.clone()
    }

    /// return the epoch hour used in the ntor handshake.
    pub fn get_epoch_hr(&self) -> String {
        self.epoch_hour.clone()
    }

    pub fn marshall(&mut self, buf: &mut impl BufMut, mut h: HmacSha256) -> Result<()> {
        trace!("serializing client handshake");

        h.reset(); // disambiguate reset() implementations Mac v digest
        h.update(self.repres.as_bytes().as_ref());
        let mark: &[u8] = &h.finalize_reset().into_bytes()[..MARK_LENGTH];

        // The client handshake is X | P_C | M_C | MAC(X | P_C | M_C | E) where:
        //  * X is the client's ephemeral Curve25519 public key representative.
        //  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
        //  * M_C is HMAC-SHA256-128(serverIdentity | NodeID, X)
        //  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, X .... E)
        //  * E is the string representation of the number of hours since the UNIX
        //    epoch.

        // Generate the padding
        let pad = make_pad(self.pad_len)?;

        // Write X, P_C, M_C
        let mut params = vec![];
        params.extend_from_slice(self.repres.as_bytes());
        params.extend_from_slice(&pad);
        params.extend_from_slice(mark);
        buf.put(params.as_slice());

        // Calculate and write MAC
        h.update(&params);
        self.epoch_hour = format!("{}", get_epoch_hour());
        h.update(self.epoch_hour.as_bytes());
        let mac = &h.finalize_reset().into_bytes()[..MARK_LENGTH];
        buf.put(mac);

        trace!("mark: {}, mac: {}", hex::encode(mark), hex::encode(mac));

        Ok(())
    }
}
