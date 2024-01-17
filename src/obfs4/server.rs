use super::{Cfg, NAME};

use crate::{traits::*, Error, Result};

#[derive(Default, Clone, Debug)]
pub struct Server {
    config: Cfg,
}

impl Server {
    fn from_config(config: Cfg) -> Result<Self> {
        Ok(Self {
            config: Self::validate_config(config)?,
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

impl Named for Server {
    fn name(&self) -> String {
        format!("{NAME}_client")
    }
}

impl TryConfigure for Server {
    fn try_config<'a>(&mut self, config: impl AsRef<[u8]> + 'a) -> Result<&mut Self> {
        let new_config = Cfg {
            s: String::from_utf8(config.as_ref().to_vec())?,
        };
        self.config = Self::validate_config(new_config)?;
        Ok(self)
    }
}

// // TODO: fix Transport impl for server
// impl Transport for Server {
//     // async fn wrap<'a>(&self, s: impl Stream<'a>) -> Result<impl Stream<'a>> {
//     fn wrap<'a>(
//         &self,
//         s: impl Stream<'a>,
//     ) -> impl Future<Output = Result<impl Stream<'a>>> + Send + Sync + 'a {
//         async { Ok(s) }
//     }
// }
