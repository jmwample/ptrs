

pub struct ORStream {}

impl ORStream {
    pub async fn connect() -> TcpStream {

    }
}

fn read_auth_cookie(_reader: impl std::io::Read) -> Result<[u8; 32], Error> {
    todo!()
}

/// Read and validate the contents of an auth cookie file. Returns the 32-byte
/// cookie. See section 2.1.2 of ext-orport-spec.txt.
fn read_auth_cookie_file(filename: impl AsRef<str>) -> Result<[u8; 32], Error> {
    let f = std::fs::File::open(filename.as_ref())?;
    read_auth_cookie(&f)
}
