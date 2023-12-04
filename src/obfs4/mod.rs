use crate::{traits::*, Result};

pub mod client;
pub mod framing;
pub mod packet;
pub mod proto;
pub mod server;

const NAME: &str = "obfs4";

#[allow(non_camel_case_types)]
pub struct Builder {
    config: Cfg,
}

impl Named for Builder {
    fn name(&self) -> String {
        String::from(NAME)
    }
}

#[derive(Default, Clone, Debug)]
struct Cfg {
    s: String,
}

impl TryConfigure for Builder {
    fn try_config<'a>(&mut self, config: impl AsRef<[u8]> + 'a) -> Result<&mut Self> {
        let s = String::from_utf8(config.as_ref().to_vec())?;
        self.config = Cfg { s };
        Ok(self)
    }
}

#[cfg(test)]
mod testing;
