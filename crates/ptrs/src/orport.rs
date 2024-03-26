use std::io::{prelude::*, BufReader, Error, ErrorKind};
use subtle::ConstantTimeEq;

const AUTH_COOKIE_HEADER: &[u8; 32] = b"! Extended ORPort Auth Cookie !\x0a";

pub struct ORStream {}

impl ORStream {
    pub async fn connect() {
        read_auth_cookie_file("").unwrap();
        todo!()
    }
}

fn read_auth_cookie(mut reader: impl BufRead) -> Result<[u8; 32], Error> {
    let mut buf = [0u8; 64];

    reader.read_exact(&mut buf)?;
    if !reader.fill_buf()?.is_empty() {
        return Err(Error::new(ErrorKind::Other, "file is longer than 64 bytes"));
    }

    let header: [u8; 32] = buf[..32].try_into().unwrap();
    let cookie: [u8; 32] = buf[32..64].try_into().unwrap();

    if header.ct_eq(AUTH_COOKIE_HEADER).unwrap_u8() == 0 {
        return Err(Error::new(ErrorKind::Other, "missing auth cookie header"));
    }

    Ok(cookie)
}

/// Read and validate the contents of an auth cookie file. Returns the 32-byte
/// cookie. See section 2.1.2 of ext-orport-spec.txt.
fn read_auth_cookie_file(filename: impl AsRef<str>) -> Result<[u8; 32], Error> {
    let f = std::fs::File::open(filename.as_ref())?;
    read_auth_cookie(BufReader::new(f))
}

#[cfg(test)]
#[serial_test::serial]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn auth_cookie() -> Result<(), Error> {
        let bad: Vec<&[u8]> = vec![
            b"",
            // bad header
            b"! Impostor ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDEF",
            // too short
            b"! Extended ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDE",
            // too long
            b"! Extended ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDEFX",
        ];
        let good = vec![b"! Extended ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDEF"];

        for trial in bad {
            let reader = Cursor::new(trial);
            assert!(
                read_auth_cookie(reader).is_err(),
                "\"{trial:?}\" unexpectedly succeeded"
            );
        }

        for trial in good {
            let reader = Cursor::new(*trial);
            match read_auth_cookie(reader) {
                Ok(cookie) => assert_eq!(cookie, trial[32..64]),
                Err(e) => panic!("\"{trial:?}\" unexpectedly returned an error: {e}"),
            }
        }

        Ok(())
    }
}
