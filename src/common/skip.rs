pub struct SkipReader<R> {
    inner: R,
    skip: usize,
    skipped: bool,
}
impl<R> SkipReader<R> {
    pub fn new(reader: R, skip: usize) -> Self {
        Self {
            inner: reader,
            skip,
            skipped: skip == 0,
        }
    }
    fn skip(&mut self) -> std::io::Result<()>
    where
        R: std::io::Read,
    {
        if self.skipped {
            return Ok(());
        }
        // N.B.: This does cost 1k of extra stack space. Be aware.
        let mut buf = [0; 1024];
        let mut total = 0;
        while total < self.skip {
            let len = std::cmp::min(self.skip - total, buf.len());
            match self.inner.read(&mut buf[..len]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            };
            debug_assert!(total <= self.skip);
        }
        self.skipped = true;
        Ok(())
    }
}
impl<R: std::io::Read> std::io::Read for SkipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.skipped {
            self.skip()?;
        }
        self.inner.read(buf)
    }
}

pub struct AsyncSkipReader<R> {
    inner: R,
    skip: usize,
    skipped: bool,
}

impl<R> AsyncDiscard<R> {
    pub fn new(reader: R) -> Self {
        Self(AsyncSkipReader {
            inner: reader,
            skip: 0,
            skipped: false,
        })
    }

    pub async fn discard(&self) {}
}

pub struct Discard<R>(SkipReader<R>);
pub struct AsyncDiscard<R>(AsyncSkipReader<R>);
