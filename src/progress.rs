use std::io::Read;

use indicatif::ProgressBar;

pub struct ProgressReader<T: Read> {
    pb: ProgressBar,
    r: T,
}

impl<T: Read> ProgressReader<T> {
    pub fn new(pb: ProgressBar, r: T) -> Self {
        Self { pb, r }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let ret = self.r.read(buf);
        if let Ok(n) = ret {
            self.pb.inc(n.try_into().unwrap());
        }
        ret
    }
}
