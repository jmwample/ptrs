use crate::{
    traits::{self}, Result,
};

pub mod handler;
pub mod wrapper;



const NAME: &str = "identity";

#[derive(Default)]
#[allow(non_camel_case_types)]
pub struct Builder {
    config: Cfg,
}

impl traits::Named for Builder {
    fn name(&self) -> String {
        String::from(NAME)
    }
}

#[derive(Default, Clone, Debug)]
struct Cfg {
    s: String,
}

impl traits::TryConfigure for Builder {
    fn try_config<'a>(&mut self, config: impl AsRef<[u8]> + 'a) -> Result<&mut Self> {
        let s = String::from_utf8(config.as_ref().to_vec())?;
        self.config = Cfg { s };
        Ok(self)
    }
}

// // TODO: fix
// // Example showing that the builder can be configured and take it's own
// // configuration into account when making a transport, which can also be
// // configured independently.
// impl traits::Builder for Builder {
//     fn handler(&self, role: &traits::Role) -> Result<impl traits::Transport> {
//         match role {
//             Role::Sender => Ok(Handler::default()),
//             Role::Receiver => match self.config.s.as_str() {
//                 "error" => Err(Error::Other("expected error".into())),
//                 _ => Ok(Handler::default()),
//             },
//             _ => Err(Error::NotSupported),
//         }
//     }
// }

/*
#[cfg(test)]
mod test {
    use super::*;
    use crate::traits::{Builder as _, Transport as _, TryConfigure};
    use futures::executor::block_on;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    #[test]
    fn basics() -> Result<()> {
        let builder_cfg = b"";
        let client_cfg = b"";
        let server_cfg = b"";

        let mut builder = Builder::default();
        let mut client_transport = builder.try_config(builder_cfg)?.handler(&Role::Sender)?;
        let client_transport = client_transport.try_config(client_cfg)?;

        let mut builder = Builder::default();
        let mut server_transport = builder.try_config(builder_cfg)?.handler(&Role::Receiver)?;
        let server_transport = server_transport.try_config(server_cfg)?;

        // imagine either creating a TCP stream or acctping one.
        let (mut conn, _) = tokio::io::duplex(128);

        let mut cc = block_on(client_transport.wrap(&mut conn))?;

        let _sc = block_on(server_transport.wrap(&mut cc))?;

        Ok(())
    }

    #[tokio::test]
    async fn tokio_basics_test() -> Result<()> {
        let msg = String::new();
        let failed = Arc::new(Mutex::new(msg));

        let client_cfg = "";
        let server_cfg = "";
        let (a, mut b) = tokio::io::duplex(128);

        let f = failed.clone();
        tokio::spawn(async move {
            let message = b"wkme;a wme09wemw qweqowme ;qwk2q3 m2 3 0eq@32 q2q23q2 q2rq2";

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            b.write_all(message).await.unwrap();

            let mut buf = vec![0_u8; message.len()];
            let _ = b.read_exact(&mut buf).await.unwrap();
            if message != buf.as_slice() {
                let mut err = f.lock().await;
                *err = format!("incorrect message read {:?}", buf);
            }

            b.shutdown().await.unwrap();
        });

        let builder = Builder::default();
        let mut client_transport = builder.handler(&Role::Sender).unwrap();
        let client_transport = client_transport.try_config(client_cfg).unwrap();

        let builder = Builder::default();
        let mut server_transport = builder.handler(&Role::Receiver).unwrap();
        let server_transport = server_transport.try_config(server_cfg).unwrap();

        let w1 = client_transport.wrap(a).await.unwrap();
        let w2 = server_transport.wrap(w1).await.unwrap();

        let (mut e1, mut e2) = tokio::io::split(w2);
        tokio::io::copy(&mut e1, &mut e2).await.unwrap();

        let res = failed.lock().await;
        if !(*res).is_empty() {
            Err(Error::from(&*res.clone()))
        } else {
            Ok(())
        }
    }
}
*/
