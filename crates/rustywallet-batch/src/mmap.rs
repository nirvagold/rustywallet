//! Memory-mapped file output for batch key generation.
//!
//! This module provides efficient file output using memory-mapped files,
//! allowing direct writes without buffering overhead.

use crate::error::BatchError;
use memmap2::MmapMut;
use rustywallet_keys::private_key::PrivateKey;
use std::fs::OpenOptions;
use std::path::Path;

/// Output format for memory-mapped file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Raw 32-byte private keys (most compact)
    Raw,
    /// Hex-encoded keys, one per line (64 chars + newline)
    Hex,
    /// WIF-encoded keys, one per line
    Wif,
}

impl OutputFormat {
    /// Get the size in bytes per key for this format.
    pub fn bytes_per_key(&self) -> usize {
        match self {
            OutputFormat::Raw => 32,
            OutputFormat::Hex => 65, // 64 hex chars + newline
            OutputFormat::Wif => 53, // ~52 chars + newline (compressed WIF)
        }
    }
}

/// Memory-mapped file writer for batch key output.
///
/// This writer uses memory-mapped files for efficient output,
/// avoiding buffering overhead and enabling direct disk writes.
///
/// # Example
///
/// ```no_run
/// use rustywallet_batch::mmap::{MmapWriter, OutputFormat};
/// use rustywallet_keys::private_key::PrivateKey;
///
/// let mut writer = MmapWriter::create("keys.txt", 1000, OutputFormat::Hex).unwrap();
///
/// for _ in 0..1000 {
///     let key = PrivateKey::random();
///     writer.write_key(&key).unwrap();
/// }
///
/// writer.finish().unwrap();
/// ```
pub struct MmapWriter {
    /// Memory-mapped region
    mmap: MmapMut,
    /// Current write position
    position: usize,
    /// Output format
    format: OutputFormat,
    /// Total capacity in keys
    capacity: usize,
    /// Number of keys written
    written: usize,
    /// File path for reference
    path: String,
}

impl MmapWriter {
    /// Create a new memory-mapped file writer.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the output file
    /// * `capacity` - Maximum number of keys to write
    /// * `format` - Output format for keys
    pub fn create<P: AsRef<Path>>(
        path: P,
        capacity: usize,
        format: OutputFormat,
    ) -> Result<Self, BatchError> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let file_size = capacity * format.bytes_per_key();

        // Create and size the file
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| BatchError::io_error(format!("Failed to create file: {}", e)))?;

        file.set_len(file_size as u64)
            .map_err(|e| BatchError::io_error(format!("Failed to set file size: {}", e)))?;

        // Memory-map the file
        let mmap = unsafe {
            MmapMut::map_mut(&file)
                .map_err(|e| BatchError::io_error(format!("Failed to mmap file: {}", e)))?
        };

        Ok(Self {
            mmap,
            position: 0,
            format,
            capacity,
            written: 0,
            path: path_str,
        })
    }

    /// Write a single key to the file.
    pub fn write_key(&mut self, key: &PrivateKey) -> Result<(), BatchError> {
        if self.written >= self.capacity {
            return Err(BatchError::io_error("Writer capacity exceeded"));
        }

        let bytes = match self.format {
            OutputFormat::Raw => {
                let b = key.to_bytes();
                self.mmap[self.position..self.position + 32].copy_from_slice(&b);
                self.position += 32;
                32
            }
            OutputFormat::Hex => {
                let hex = key.to_hex();
                let line = format!("{}\n", hex);
                let bytes = line.as_bytes();
                self.mmap[self.position..self.position + bytes.len()].copy_from_slice(bytes);
                self.position += bytes.len();
                bytes.len()
            }
            OutputFormat::Wif => {
                let wif = key.to_wif(rustywallet_keys::network::Network::Mainnet);
                let line = format!("{}\n", wif);
                let bytes = line.as_bytes();
                self.mmap[self.position..self.position + bytes.len()].copy_from_slice(bytes);
                self.position += bytes.len();
                bytes.len()
            }
        };

        self.written += 1;
        let _ = bytes; // suppress unused warning
        Ok(())
    }

    /// Write multiple keys to the file.
    pub fn write_keys(&mut self, keys: &[PrivateKey]) -> Result<usize, BatchError> {
        let mut count = 0;
        for key in keys {
            if self.written >= self.capacity {
                break;
            }
            self.write_key(key)?;
            count += 1;
        }
        Ok(count)
    }

    /// Get the number of keys written.
    pub fn written(&self) -> usize {
        self.written
    }

    /// Get the remaining capacity.
    pub fn remaining(&self) -> usize {
        self.capacity - self.written
    }

    /// Get the file path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Finish writing and truncate file to actual size.
    pub fn finish(self) -> Result<usize, BatchError> {
        // Flush the mmap
        self.mmap
            .flush()
            .map_err(|e| BatchError::io_error(format!("Failed to flush mmap: {}", e)))?;

        // Truncate file to actual written size
        let file = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| BatchError::io_error(format!("Failed to open file for truncate: {}", e)))?;

        file.set_len(self.position as u64)
            .map_err(|e| BatchError::io_error(format!("Failed to truncate file: {}", e)))?;

        Ok(self.written)
    }
}

/// Batch file generator using memory-mapped output.
///
/// Combines batch generation with memory-mapped file output
/// for maximum throughput.
pub struct MmapBatchGenerator {
    /// Output path
    path: String,
    /// Number of keys to generate
    count: usize,
    /// Output format
    format: OutputFormat,
    /// Chunk size for parallel generation
    chunk_size: usize,
    /// Use parallel generation
    parallel: bool,
}

impl MmapBatchGenerator {
    /// Create a new mmap batch generator.
    pub fn new<P: AsRef<Path>>(path: P, count: usize) -> Self {
        Self {
            path: path.as_ref().to_string_lossy().to_string(),
            count,
            format: OutputFormat::Hex,
            chunk_size: 10_000,
            parallel: true,
        }
    }

    /// Set the output format.
    pub fn format(mut self, format: OutputFormat) -> Self {
        self.format = format;
        self
    }

    /// Set the chunk size for parallel generation.
    pub fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Enable or disable parallel generation.
    pub fn parallel(mut self, enabled: bool) -> Self {
        self.parallel = enabled;
        self
    }

    /// Generate keys and write directly to file.
    pub fn generate(self) -> Result<usize, BatchError> {
        use crate::fast_gen::FastKeyGenerator;

        let mut writer = MmapWriter::create(&self.path, self.count, self.format)?;

        // Generate in chunks to balance memory and parallelism
        let mut remaining = self.count;
        while remaining > 0 {
            let chunk_count = remaining.min(self.chunk_size);
            let keys = FastKeyGenerator::new(chunk_count)
                .parallel(self.parallel)
                .generate();

            writer.write_keys(&keys)?;
            remaining -= chunk_count;
        }

        writer.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_mmap_writer_hex() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.txt");

        let mut writer = MmapWriter::create(&path, 100, OutputFormat::Hex).unwrap();

        for _ in 0..100 {
            let key = PrivateKey::random();
            writer.write_key(&key).unwrap();
        }

        let written = writer.finish().unwrap();
        assert_eq!(written, 100);

        // Verify file content
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 100);
        assert!(lines.iter().all(|l| l.len() == 64));
    }

    #[test]
    fn test_mmap_writer_raw() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.bin");

        let mut writer = MmapWriter::create(&path, 50, OutputFormat::Raw).unwrap();

        for _ in 0..50 {
            let key = PrivateKey::random();
            writer.write_key(&key).unwrap();
        }

        let written = writer.finish().unwrap();
        assert_eq!(written, 50);

        // Verify file size
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 50 * 32);
    }

    #[test]
    fn test_mmap_batch_generator() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("batch.txt");

        let written = MmapBatchGenerator::new(&path, 1000)
            .format(OutputFormat::Hex)
            .chunk_size(100)
            .parallel(true)
            .generate()
            .unwrap();

        assert_eq!(written, 1000);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 1000);
    }
}
