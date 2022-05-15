use std::fs;
use std::io::{self, Read, Seek};
use std::path::PathBuf;
use std::sync::Arc;

pub struct ClonableFile {
    path: Arc<PathBuf>,
    file: Option<fs::File>,
}

impl ClonableFile {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
            file: None,
        }
    }

    pub fn file(&mut self) -> io::Result<&mut fs::File> {
        // TODO: using if let syntax here results in a compiler error but is a
        //       better way to implement it.
        if self.file.is_some() {
            return Ok(self.file.as_mut().unwrap());
        }

        let f = fs::File::open(self.path.as_ref())?;
        Ok(self.file.insert(f))
    }
}

impl Clone for ClonableFile {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            file: None,
        }
    }
}

impl Read for ClonableFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let f = self.file()?;
        f.read(buf)
    }
}

impl Seek for ClonableFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let f = self.file()?;
        f.seek(pos)
    }
}
