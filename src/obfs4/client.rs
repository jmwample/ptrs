use super::{Cfg, NAME};
use futures::Future;

use super::proto::Client as InnerClient;
use crate::{stream::Stream, traits::*, Error, Result};

#[derive(Default)]
pub struct Client {
    config: Cfg,
    client: Option<InnerClient>,
}

impl Client {
    fn from_config(config: Cfg) -> Result<Self> {
        Ok(Self {
            config: Self::validate_config(config)?,
            client: None,
        })
    }

    fn validate_config(config: Cfg) -> Result<Cfg> {
        if config.s == "error" {
            Err(Error::Other("intentional error".into()))
        } else {
            Ok(config)
        }
    }
}

impl Named for Client {
    fn name(&self) -> String {
        format!("{NAME}_client")
    }
}

impl TryConfigure for Client {
    fn try_config<'a>(&mut self, config: impl AsRef<[u8]> + 'a) -> Result<&mut Self> {
        let new_config = Cfg {
            s: String::from_utf8(config.as_ref().to_vec())?,
        };
        self.config = Self::validate_config(new_config)?;
        Ok(self)
    }
}

impl Transport for Client {
    // async fn wrap<'a>(&self, s: impl Stream<'a>) -> Result<impl Stream<'a>> {
    fn wrap<'a>(
        &self,
        s: impl Stream<'a>,
    ) -> impl Future<Output = Result<impl Stream<'a>>> + Send + Sync + 'a {
        async { Ok(s) }
    }
}
