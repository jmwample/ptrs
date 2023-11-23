use super::{Cfg, NAME};
use futures::Future;

use crate::{stream::Stream, traits::*, Error, Result};

#[derive(Default, Clone, Debug)]
pub struct Handler {
    config: Cfg,
    is_server: bool,
}

impl Handler {
    fn as_role(role: &Role) -> Result<Self> {
        match role {
            Role::Sender => Ok(Self {
                config: Cfg::default(),
                is_server: false,
            }),
            Role::Receiver => Ok(Self {
                config: Cfg::default(),
                is_server: true,
            }),
            _ => Err(Error::NotSupported),
        }
    }
}

impl Named for Handler {
    fn name(&self) -> String {
        format!("{NAME}_client")
    }
}

impl TryConfigure for Handler {
    fn try_config<'a>(&mut self, config: impl AsRef<[u8]> + 'a) -> Result<&mut Self> {
        self.config = Cfg {
            s: String::from_utf8(config.as_ref().to_vec())?,
        };
        Ok(self)
    }
}

impl Transport for Handler {
    fn wrap<'a>(
        &self,
        s: impl Stream<'a>,
    ) -> impl Future<Output = Result<impl Stream<'a>>> + Send + Sync + 'a {
        async { Ok(s) }
    }
}
