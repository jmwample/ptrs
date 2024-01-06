

use crate::Result;

use std::marker::PhantomData;

/// PlaceHolder
trait ClientSessionState {}

struct ClientHandshake<S:ClientHandshakeState> {
    _h_state: S,
}

impl<S:ClientHandshakeState> ClientSessionState for ClientHandshake<S> {}

trait ClientHandshakeState {}

struct ClientHandshakeSent {}
struct ServerHandshakeReceived {}
struct ClientHandshakeSuccess {}

impl ClientHandshakeState for ClientHandshakeSent {}
impl ClientHandshakeState for ServerHandshakeReceived {}
impl ClientHandshakeState for ClientHandshakeSuccess {}

impl<S:ClientHandshakeState> ClientHandshake<S> {
    fn to_inner(self) -> impl ClientHandshakeState {
        self._h_state
    }
}

pub(crate) fn start() -> ClientHandshake<ClientHandshakeSent> {
    ClientHandshake { _h_state: ClientHandshakeSent {  } }
}


impl ClientHandshake<ClientHandshakeSent> {
    pub fn handle_server_response(mut self) -> Result<ClientHandshake<ServerHandshakeReceived>>{
        Ok(self.transition())
    }
}

impl ClientHandshake<ServerHandshakeReceived> {
    pub fn handshake_complete(mut self) -> ClientHandshake<ClientHandshakeSuccess>{
        self.transition()
    }
}

