use crate::{
    common::{
        utils::{get_epoch_hour, make_pad},
        HmacSha256,
    },
    constants::*,
    handshake::{
        decrypt, encrypt, Authcode, CHSMaterials, EphemeralPub, SessionSharedSecret,
        AUTHCODE_LENGTH, ENC_KEY_LEN,
    },
    Error, Result,
};

use block_buffer::Eager;
use bytes::{BufMut, BytesMut};
use digest::{
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    HashMarker,
};
use hmac::{Hmac, Mac};
use kem::{Decapsulate, Encapsulate};
use kemeleon::{Encode, OKemCore};
use ptrs::trace;
use rand::Rng;
use rand_core::CryptoRngCore;
use sha3::Sha3_256;
use tor_bytes::{EncodeError, EncodeResult};
use tor_cell::relaycell::extend::NtorV3Extension;
use typenum::{consts::U256, marker_traits::NonZero, operator_aliases::Le, type_operators::IsLess};
use zeroize::{Zeroize, Zeroizing};

use core::borrow::Borrow;

// -----------------------------[ Server ]-----------------------------

pub struct ServerHandshakeMessage<K:OKemCore> {
    server_auth: [u8; AUTHCODE_LENGTH],
    pad_len: usize,
    session_pubkey: EphemeralPub<K>,
    epoch_hour: String,
    aux_data: Vec<NtorV3Extension>,
}

impl<K:OKemCore> ServerHandshakeMessage<K> {
    pub fn new(_client_pubkey: EphemeralPub<K>, _session_pubkey: EphemeralPub<K>) -> Self {
        todo!("SHS MSG - this should probably be built directly from the client HS MSG");
        // Self {
        //     server_auth: [0u8; AUTHCODE_LENGTH],
        //     pad_len: rand::thread_rng().gen_range(SERVER_MIN_PAD_LENGTH..SERVER_MAX_PAD_LENGTH),
        //     epoch_hour: epoch_hr,
        // }
    }

    pub fn with_pad_len(&mut self, pad_len: usize) -> &Self {
        self.pad_len = pad_len;
        self
    }

    pub fn with_aux_data(&mut self, aux_data: Vec<NtorV3Extension>) -> &Self {
        self.aux_data = aux_data;
        self
    }

    pub fn server_pubkey(&mut self) -> EphemeralPub<K> {
        self.session_pubkey.clone()
    }

    pub fn server_auth(self) -> Authcode {
        self.server_auth
    }

    pub fn marshall(&mut self, _buf: &mut impl BufMut, mut _h: HmacSha256) -> Result<()> {
        trace!("serializing server handshake");
        todo!("marshall server hello");

        // h.reset();
        // h.update(self.session_pubkey.as_bytes().as_ref());
        // let mark: &[u8] = &h.finalize_reset().into_bytes()[..MARK_LENGTH];

        // // The server handshake is Y | AUTH | P_S | M_S | MAC(Y | AUTH | P_S | M_S | E) where:
        // //  * Y is the server's ephemeral Curve25519 public key representative.
        // //  * AUTH is the ntor handshake AUTH value.
        // //  * P_S is [serverMinPadLength,serverMaxPadLength] bytes of random padding.
        // //  * M_S is HMAC-SHA256-128(serverIdentity | NodeID, Y)
        // //  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, Y .... E)
        // //  * E is the string representation of the number of hours since the UNIX
        // //    epoch.

        // // Generate the padding
        // let pad: &[u8] = &make_pad(rng, self.pad_len)?;

        // // Write Y, AUTH, P_S, M_S.
        // let mut params = vec![];
        // params.extend_from_slice(self.session_pubkey.as_bytes());
        // params.extend_from_slice(&self.server_auth);
        // params.extend_from_slice(pad);
        // params.extend_from_slice(mark);
        // buf.put(params.as_slice());

        // // Calculate and write MAC
        // h.update(&params);
        // h.update(self.epoch_hour.as_bytes());
        // buf.put(&h.finalize_reset().into_bytes()[..MAC_LENGTH]);

        // Ok(())
    }
}

// -----------------------------[ Client ]-----------------------------

/// Preliminary message sent in an obfs4 handshake attempting to open a
/// connection from a client to a potential server.
pub struct ClientHandshakeMessage<K: OKemCore> {
    hs_materials: CHSMaterials<K>,
    client_session_pubkey: EphemeralPub<K>,

    // only used when parsing (i.e. on the server side)
    pub(crate) epoch_hour: String,
}

impl<K> ClientHandshakeMessage<K>
where
    K: OKemCore,
    <K as OKemCore>::EncapsulationKey: Clone,
{
    pub(crate) fn new(
        client_session_pubkey: EphemeralPub<K>,
        hs_materials: CHSMaterials<K>,
    ) -> Self {
        Self {
            hs_materials,
            client_session_pubkey,

            // only used when parsing (i.e. on the server side)
            epoch_hour: get_epoch_hour().to_string(),
        }
    }

    pub fn get_public(&mut self) -> K::EncapsulationKey {
        // trace!("repr: {}", hex::encode(self.client_session_pubkey.id);
        self.client_session_pubkey.clone()
    }

    /// return the epoch hour used in the ntor handshake.
    pub fn get_epoch_hr(&self) -> String {
        self.epoch_hour.clone()
    }

    /// The client handshake is constructed as:
    ///    ES = F2(NodeID, shared_secret_1)
    ///    MSG = Enc_chacha20poly1305(ES, [extensions])
    ///    Mc = F1(ES, EKco | CTco | ":mc")
    ///    MACc = F1(ES, EKco | CTco | MSG | P_C | Mc | E | ":mac_c" )
    ///    OUT = EKco | CTco | MSG | P_C | Mc | MACc
    ///
    /// where
    ///    EKco is the client's ephemeral encapsulation key encoded in obfuscated form
    ///    CTco is  client_ciphertext_obfuscated
    ///    E is the string representation of the number of hours since the UNIX epoch.
    ///    P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
    pub fn marshall(
        &mut self,
        rng: &mut impl CryptoRngCore,
        buf: &mut impl BufMut,
    ) -> EncodeResult<Zeroizing<[u8; ENC_KEY_LEN]>> {
        trace!("serializing client handshake");
        self.marshall_inner::<Sha3_256>(rng, buf)
    }

    fn marshall_inner<D>(
        &mut self,
        rng: &mut impl CryptoRngCore,
        buf: &mut impl BufMut,
    ) -> EncodeResult<Zeroizing<[u8; ENC_KEY_LEN]>>
    where
        D: CoreProxy,
        D::Core: HashMarker
            + UpdateCore
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    {
        // serialize our extensions into a message
        let mut message = BytesMut::new();
        NtorV3Extension::write_many_onto(self.hs_materials.aux_data.borrow(), &mut message)?;

        // -------------------------------- [ ST-PQ-OBFS ] -------------------------------- //
        // Security Theoretic, Post-Quantum safe, Obfuscated Key exchange

        let node_encap_key = &self.hs_materials.node_pubkey.ek;
        let node_id = &self.hs_materials.node_pubkey.id;
        let (ciphertext, shared_secret) = node_encap_key.encapsulate(rng).map_err(to_tor_err)?;

        // compute our ephemeral secret
        let mut h =
            Hmac::<D>::new_from_slice(node_id.as_bytes()).expect("keying hmac should never fail");
        h.update(shared_secret.as_bytes());
        let mut ephemeral_secret = Zeroizing::new([0u8; ENC_KEY_LEN]);
        ephemeral_secret.copy_from_slice(&h.finalize_reset().into_bytes()[..ENC_KEY_LEN]);

        // set up our hash fn
        let mut f1_es = Hmac::<D>::new_from_slice(ephemeral_secret.as_ref())
            .expect("keying hmac should never fail");

        // compute the Mark
        f1_es.update(&self.client_session_pubkey.as_bytes()[..]);
        f1_es.update(&ciphertext.as_bytes()[..]);
        f1_es.update(MARK_ARG.as_bytes());
        let mark = f1_es.finalize_reset().into_bytes();

        // Encrypt the message (Extensions etc.)
        //
        // note that these do not benefit from forward secrecy, i.e. if the servers long term
        // identity secret key is leaked this text can be decrypted. Once we receive the
        // server response w/ secrets based on ephemeral (session) secrets any further data has
        // forward secrecy.
        let encrypted_msg = encrypt(&ephemeral_secret, &message);

        // Generate the padding
        let pad_len = rng.gen_range(CLIENT_MIN_PAD_LENGTH..CLIENT_MAX_PAD_LENGTH); // TODO - recalculate these
        let pad = make_pad(rng, pad_len);

        // Write EKco, CTco, MSG, P_C, M_C
        let mut params = vec![];
        params.extend_from_slice(&self.client_session_pubkey.as_bytes()[..]);
        params.extend_from_slice(&ciphertext.as_bytes()[..]);
        params.extend_from_slice(&message);
        params.extend_from_slice(&pad);
        params.extend_from_slice(&mark);
        buf.put(params.as_slice());

        // Calculate and write MAC
        f1_es.update(&params);
        self.epoch_hour = format!("{}", get_epoch_hour());
        f1_es.update(self.epoch_hour.as_bytes());
        f1_es.update(CLIENT_MAC_ARG.as_bytes());
        let mac = f1_es.finalize_reset().into_bytes();
        buf.put(&mac[..]);

        trace!(
            "{} - mark: {}, mac: {}",
            self.hs_materials.session_id,
            hex::encode(mark),
            hex::encode(mac)
        );

        Ok(ephemeral_secret)
    }
}

fn to_tor_err(e: impl core::fmt::Debug) -> EncodeError {
    tor_bytes::EncodeError::from(tor_error::Bug::new(
        tor_error::ErrorKind::Other,
        format!("cryptographic encapsulation error: {e:?}"),
    ))
}
// The client handshake is X | P_C | M_C | MAC(X | P_C | M_C | E) where:
//  * X is the client's ephemeral Curve25519 public key representative.
//  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
//  * M_C is HMAC-SHA256-128(serverIdentity | NodeID, X)
//  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, X .... E)
//  * E is the string representation of the number of hours since the UNIX epoch.
