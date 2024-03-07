use crate::{
    stream::Stream,
    Result, // Error,
};

use futures::Future;

use std::net::SocketAddr;

// ==================== Common =====================

pub trait Named {
    fn name(&self) -> String;
}

pub trait TryConfigure {
    fn try_config<'a>(&mut self, config: impl AsRef<[u8]> + 'a) -> Result<&mut Self>;
}

// ==================== Wrapper =====================

#[derive(Clone, Debug)]
pub enum Role {
    Sender,
    Receiver,
    Peer,
}

pub trait Builder {
    fn build(&self, r: &Role) -> Result<impl Wrap + Send + Sync>;
}

pub trait Wrap: TryConfigure + Named {
    fn wrap<'a>(
        &self,
        s: impl Stream<'a>,
    ) -> impl Future<Output = Result<impl Stream<'a>>> + Send + Sync + 'a;
}

// ==================== Dialer =====================

// On hold for now
pub trait Dialer: TryConfigure + Named {
    fn connect<'a>(&self, addr: SocketAddr) -> impl Future<Output = Result<impl Stream<'a> + 'a>>;
}

// ==================== listener =====================

// On hold for now
pub trait ListenBuilder: TryConfigure + Named {
    fn bind<'a>(&self, laddr: SocketAddr) -> impl Future<Output = Result<impl Listen>>;
}

pub trait Listen {
    fn accept<'a>(
        &self,
        laddr: SocketAddr,
    ) -> impl Future<Output = Result<(impl Stream<'a>, SocketAddr)>>;
}

// ==================== Peer =====================

// On hold for now
pub trait PeerBuilder: TryConfigure + Named {
    fn bind<'a>(&self, laddr: SocketAddr) -> impl Future<Output = Result<impl Peer>>;
}

pub trait Peer {
    fn recv();
    fn send();
    fn recv_from();
    fn send_to();
}

// ==================== Testing =====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_transport_api() -> Result<()> {
        Ok(())
    }
}
/*
    #[derive(Default)]
    struct Client {}

    impl Named for Client {
        fn name(&self) -> String {
            "mock_client".into()
        }
    }

    impl Ingress for Client {}
    impl TryConfigure for Client {
        fn try_config<'a>(&mut self, _config: impl AsRef<[u8]> + 'a) -> Result<()>{
            Ok(())
        }
    }

    impl Transport for Client {
        fn wrap<'a>(&self, s: impl Stream<'a>) -> impl Future<Output=Result<impl Stream<'a>>>  {
            async {
                // let mut r = &[0_u8; 128][..];
                // let w = vec![0_u8; 128];
                // let rw = crate::stream::combine(&mut r, w);
                Ok(s)
                // Err(Error::Other("mock".into()))
            }
        }
    }

    #[derive(Default)]
    struct Server {}

    impl Named for Server {
        fn name(&self) -> String {
            "mock_server".into()
        }
    }

    impl Egress for Server {}
    impl TryConfigure for Server {
        fn try_config<'a>(&mut self, _config: impl AsRef<[u8]> + 'a) -> Result<()> {
            Ok(())
        }
    }

    impl Transport for Server {
        fn wrap<'a>(&self, s: impl Stream<'a>) -> impl Future<Output=Result<impl Stream<'a>>>  {
            async {
                Ok(Box::new(s))
                // Err(Error::Other("mock".into()))
            }
        }
    }

    #[derive(Default)]
    struct MockTransport {}

    impl Named for MockTransport {
        fn name(&self) -> String {
            "mock_transport".into()
        }
    }

    impl IngressBuilder for MockTransport {
        fn client(&self) -> Result<Client> {
            Ok(Client::default())
            // Err(Error::Other("not implemented".into()))
        }
    }

    impl EgressBuilder for MockTransport {
        fn server(&self) -> Result<Server> {
            Ok(Server::default())
            // Err(Error::Other("not implemented".into()))
        }
    }

    impl Builder for MockTransport {}

    #[test]
    fn transport_api() -> Result<()> {
        let builder = &MockTransport::default();

        // let mut client = Client::default();
        let mut client = builder.client()?;
        client.try_config(b"testing:true")?;
        assert_eq!("mock_client", client.name());


        let mut server = builder.server()?;
        server.try_config(b"testing:true")?;
        assert_eq!("mock_server", server.name());

        // let t: &mut dyn Builder = &mut MockTransport::new();
        // println!("{}", t.name());

        Ok(())
    }
}
*/
