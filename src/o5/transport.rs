use crate::traits::*;
use std::error::Error;


const NAME: &'static str = "o7";

#[allow(non_camel_case_types)]
pub struct o7 {}

impl Named for o7 {
    fn name() -> &'static str {
        NAME
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct Client {}
impl Named for Client {
    fn name() -> &'static str {
        NAME+"_client"
    }
}


#[derive(Default, Clone, Copy, Debug)]
pub struct Server {}
impl Named for Server {
    fn name() -> &'static str {
        NAME+"_server"
    }
}

struct Cfg {
    s: String
}

impl ToConfig for Cfg {}
impl From<&'static str> for Cfg {
    fn from(s: &'static str) -> Self {
        Cfg { s: s.to_string() }
    }
}

impl From<dyn Iterator<Item=u8>> for Cfg {
    fn from(s: dyn Iterator<Item=u8>) -> Self {
        Cfg { s: s.try_collect().unwrap()}
    }
}


impl Ingress for Client {}
impl Configurable for Client  {
    fn with_config(mut self, cfg: Cfg)-> Result<Self, dyn Error> {
        Ok(self)
    }
}

impl Egress for Server {}
impl Configurable for Server  {
    fn with_config(mut self, cfg: Cfg)-> Result<Self, dyn Error> {
        Ok(self)
    }
}

impl IngressBuilder for o7 {
    fn client() -> Result<Client, dyn Error> {
        Ok(Client::default())
    }
}

impl EgressBuilder for o7 {
    fn server(args: Option<()>) -> Result<Server, dyn Error> {
        Ok(())
    }
}
