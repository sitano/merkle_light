use std::fs::{File, OpenOptions};
use std::marker::PhantomData;
use std::ops;
use std::path::{Path, PathBuf};

use anyhow::Result;
use memmap::MmapMut;

use crate::merkle::Element;
use crate::store::{Store, StoreConfig};

/// Store that saves the data on disk, and accesses it using memmap.
#[derive(Debug)]
pub struct MmapStore<E: Element> {
    path: PathBuf,
    map: Option<MmapMut>,
    store_size: usize,
    _e: PhantomData<E>,
}

impl<E: Element> ops::Deref for MmapStore<E> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.map.as_ref().unwrap()[..]
    }
}

impl<E: Element> Store<E> for MmapStore<E> {
    #[allow(unsafe_code)]
    fn new_with_config(size: usize, config: StoreConfig) -> Result<Self> {
        let data_path = StoreConfig::data_path(&config.path, &config.id);

        // If the specified file exists, load it from disk.
        if Path::new(&data_path).exists() {
            return Self::new_from_disk(size, &config);
        }

        // Otherwise, create the file and allow it to be the on-disk store.
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(data_path)?;

        let store_size = E::byte_len() * size;
        file.set_len(store_size as u64)?;

        let map = unsafe { MmapMut::map_mut(&file)? };

        Ok(MmapStore {
            path: data_path,
            _e: Default::default(),
            map: Some(map),
            store_size,
        })
    }

    #[allow(unsafe_code)]
    fn new(size: usize) -> Result<Self> {
        let store_size = E::byte_len() * size;
        let file = tempfile::NamedTempFile::new()?;
        file.as_file().set_len(store_size as u64)?;
        let (file, path) = file.into_parts();
        let map = unsafe { MmapMut::map_mut(&file)? };

        Ok(MmapStore {
            path: path.keep()?,
            _e: Default::default(),
            map: Some(map),
            store_size,
        })
    }

    fn write_at(&mut self, el: E, index: usize) -> Result<()> {
        if self.0.len() <= index {
            self.0.resize(index + 1, E::default());
        }

        self.0[index] = el;
        Ok(())
    }

    // NOTE: Performance regression. To conform with the current API we are
    // unnecessarily converting to and from `&[u8]` in the `MmapStore` which
    // already stores `E` (in contrast with the `mmap` versions). We are
    // prioritizing performance for the `mmap` case which will be used in
    // production (`MmapStore` is mainly for testing and backwards compatibility).
    fn copy_from_slice(&mut self, buf: &[u8], start: usize) -> Result<()> {
        ensure!(
            buf.len() % E::byte_len() == 0,
            "buf size must be a multiple of {}",
            E::byte_len()
        );
        let num_elem = buf.len() / E::byte_len();

        if self.0.len() < start + num_elem {
            self.0.resize(start + num_elem, E::default());
        }

        self.0.splice(
            start..start + num_elem,
            buf.chunks_exact(E::byte_len()).map(E::from_slice),
        );
        Ok(())
    }

    fn new_from_slice_with_config(size: usize, data: &[u8], config: StoreConfig) -> Result<Self> {
        ensure!(
            data.len() % E::byte_len() == 0,
            "data size must be a multiple of {}",
            E::byte_len()
        );

        let mut store = Self::new_with_config(size, config)?;

        // If the store was loaded from disk (based on the config
        // information, avoid re-populating the store at this point
        // since it can be assumed by the config that the data is
        // already correct).
        if !store.loaded_from_disk {
            store.store_copy_from_slice(0, data)?;
            store.len = data.len() / store.elem_len;
        }

        Ok(store)
    }

    fn new_from_slice(size: usize, data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() % E::byte_len() == 0,
            "data size must be a multiple of {}",
            E::byte_len()
        );

        let mut store = Self::new(size)?;
        store.store_copy_from_slice(0, data)?;
        store.len = data.len() / store.elem_len;

        Ok(store)
    }

    #[allow(unsafe_code)]
    fn new_from_disk(size: usize, config: &StoreConfig) -> Result<Self> {
        let data_path = StoreConfig::data_path(&config.path, &config.id);

        let file = File::open(&data_path)?;
        let metadata = file.metadata()?;
        let store_size = metadata.len() as usize;

        // Sanity check.
        ensure!(
            store_size == size * E::byte_len(),
            "Invalid formatted file provided. Expected {} bytes, found {} bytes",
            size * E::byte_len(),
            store_size
        );

        let map = unsafe { MmapMut::map_mut(file)? };

        Ok(MmapStore {
            _e: Default::default(),
            store_size,
            map: Some(map),
        })
    }

    fn read_at(&self, index: usize) -> Result<E> {
        Ok(self.0[index].clone())
    }

    fn read_into(&self, index: usize, buf: &mut [u8]) -> Result<()> {
        self.0[index].copy_to_slice(buf);
        Ok(())
    }

    fn read_range_into(&self, _start: usize, _end: usize, _buf: &mut [u8]) -> Result<()> {
        unimplemented!("Not required here");
    }

    fn read_range(&self, r: ops::Range<usize>) -> Result<Vec<E>> {
        Ok(self.0.index(r).to_vec())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn loaded_from_disk(&self) -> bool {
        false
    }

    fn compact(&mut self, _config: StoreConfig, _store_version: u32) -> Result<bool> {
        self.0.shrink_to_fit();

        Ok(true)
    }

    fn delete(_config: StoreConfig) -> Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn push(&mut self, el: E) -> Result<()> {
        self.0.push(el);
        Ok(())
    }
}
