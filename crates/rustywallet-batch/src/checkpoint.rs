//! Checkpoint and resume support for batch generation.
//!
//! This module provides checkpoint functionality to save and resume
//! batch generation progress, useful for long-running operations.

use crate::error::BatchError;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Checkpoint data for resumable batch generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Unique job identifier
    pub job_id: String,
    /// Total keys to generate
    pub total_count: usize,
    /// Keys generated so far
    pub generated_count: usize,
    /// Output file path
    pub output_path: String,
    /// Last key generated (hex)
    pub last_key: Option<String>,
    /// Timestamp of last update
    pub updated_at: u64,
    /// Generation mode
    pub mode: GenerationMode,
    /// Starting key for incremental mode
    pub start_key: Option<String>,
    /// Current position for incremental mode
    pub current_position: u64,
}

/// Generation mode for checkpointing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GenerationMode {
    /// Random key generation
    Random,
    /// Incremental key generation from a starting point
    Incremental,
}

impl Checkpoint {
    /// Create a new checkpoint for random generation.
    pub fn new_random(job_id: &str, total_count: usize, output_path: &str) -> Self {
        Self {
            job_id: job_id.to_string(),
            total_count,
            generated_count: 0,
            output_path: output_path.to_string(),
            last_key: None,
            updated_at: current_timestamp(),
            mode: GenerationMode::Random,
            start_key: None,
            current_position: 0,
        }
    }

    /// Create a new checkpoint for incremental generation.
    pub fn new_incremental(
        job_id: &str,
        total_count: usize,
        output_path: &str,
        start_key: &str,
    ) -> Self {
        Self {
            job_id: job_id.to_string(),
            total_count,
            generated_count: 0,
            output_path: output_path.to_string(),
            last_key: None,
            updated_at: current_timestamp(),
            mode: GenerationMode::Incremental,
            start_key: Some(start_key.to_string()),
            current_position: 0,
        }
    }

    /// Update checkpoint with progress.
    pub fn update(&mut self, generated: usize, last_key: Option<String>) {
        self.generated_count = generated;
        self.last_key = last_key;
        self.updated_at = current_timestamp();
    }

    /// Update position for incremental mode.
    pub fn update_position(&mut self, position: u64) {
        self.current_position = position;
        self.updated_at = current_timestamp();
    }

    /// Check if generation is complete.
    pub fn is_complete(&self) -> bool {
        self.generated_count >= self.total_count
    }

    /// Get remaining keys to generate.
    pub fn remaining(&self) -> usize {
        self.total_count.saturating_sub(self.generated_count)
    }

    /// Get progress as percentage.
    pub fn progress_percent(&self) -> f64 {
        if self.total_count == 0 {
            100.0
        } else {
            (self.generated_count as f64 / self.total_count as f64) * 100.0
        }
    }

    /// Save checkpoint to file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), BatchError> {
        let file = File::create(path)
            .map_err(|e| BatchError::io_error(format!("Failed to create checkpoint file: {}", e)))?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)
            .map_err(|e| BatchError::io_error(format!("Failed to write checkpoint: {}", e)))?;
        Ok(())
    }

    /// Load checkpoint from file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, BatchError> {
        let file = File::open(path)
            .map_err(|e| BatchError::io_error(format!("Failed to open checkpoint file: {}", e)))?;
        let reader = BufReader::new(file);
        let checkpoint: Self = serde_json::from_reader(reader)
            .map_err(|e| BatchError::io_error(format!("Failed to parse checkpoint: {}", e)))?;
        Ok(checkpoint)
    }

    /// Check if checkpoint file exists.
    pub fn exists<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref().exists()
    }

    /// Delete checkpoint file.
    pub fn delete<P: AsRef<Path>>(path: P) -> Result<(), BatchError> {
        if path.as_ref().exists() {
            fs::remove_file(path)
                .map_err(|e| BatchError::io_error(format!("Failed to delete checkpoint: {}", e)))?;
        }
        Ok(())
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resumable batch generator with checkpoint support.
///
/// This generator can save progress and resume from where it left off,
/// useful for generating very large batches of keys.
///
/// # Example
///
/// ```no_run
/// use rustywallet_batch::checkpoint::ResumableBatchGenerator;
/// use rustywallet_batch::mmap::OutputFormat;
///
/// // Start or resume generation
/// let mut generator = ResumableBatchGenerator::new(
///     "my-job",
///     1_000_000,
///     "keys.txt",
///     "checkpoint.json",
/// );
///
/// generator.generate_with_progress(|progress| {
///     println!("Progress: {:.1}%", progress);
/// }).unwrap();
/// ```
pub struct ResumableBatchGenerator {
    /// Checkpoint data
    checkpoint: Checkpoint,
    /// Checkpoint file path
    checkpoint_path: String,
    /// Chunk size for generation
    chunk_size: usize,
    /// Checkpoint interval (keys between saves)
    checkpoint_interval: usize,
    /// Use parallel generation
    parallel: bool,
}

impl ResumableBatchGenerator {
    /// Create a new resumable generator.
    ///
    /// If a checkpoint exists, it will be loaded and generation will resume.
    pub fn new(job_id: &str, total_count: usize, output_path: &str, checkpoint_path: &str) -> Self {
        let checkpoint = if Checkpoint::exists(checkpoint_path) {
            Checkpoint::load(checkpoint_path).unwrap_or_else(|_| {
                Checkpoint::new_random(job_id, total_count, output_path)
            })
        } else {
            Checkpoint::new_random(job_id, total_count, output_path)
        };

        Self {
            checkpoint,
            checkpoint_path: checkpoint_path.to_string(),
            chunk_size: 10_000,
            checkpoint_interval: 100_000,
            parallel: true,
        }
    }

    /// Create a new resumable generator for incremental mode.
    pub fn new_incremental(
        job_id: &str,
        total_count: usize,
        output_path: &str,
        checkpoint_path: &str,
        start_key: &str,
    ) -> Self {
        let checkpoint = if Checkpoint::exists(checkpoint_path) {
            Checkpoint::load(checkpoint_path).unwrap_or_else(|_| {
                Checkpoint::new_incremental(job_id, total_count, output_path, start_key)
            })
        } else {
            Checkpoint::new_incremental(job_id, total_count, output_path, start_key)
        };

        Self {
            checkpoint,
            checkpoint_path: checkpoint_path.to_string(),
            chunk_size: 10_000,
            checkpoint_interval: 100_000,
            parallel: true,
        }
    }

    /// Set the chunk size for generation.
    pub fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Set the checkpoint interval.
    pub fn checkpoint_interval(mut self, interval: usize) -> Self {
        self.checkpoint_interval = interval;
        self
    }

    /// Enable or disable parallel generation.
    pub fn parallel(mut self, enabled: bool) -> Self {
        self.parallel = enabled;
        self
    }

    /// Get current progress.
    pub fn progress(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// Generate keys with progress callback.
    pub fn generate_with_progress<F>(&mut self, mut progress_callback: F) -> Result<usize, BatchError>
    where
        F: FnMut(f64),
    {
        use crate::fast_gen::FastKeyGenerator;
        use std::fs::OpenOptions;
        use std::io::Write;

        if self.checkpoint.is_complete() {
            return Ok(self.checkpoint.generated_count);
        }

        // Open output file in append mode if resuming
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.checkpoint.output_path)
            .map_err(|e| BatchError::io_error(format!("Failed to open output file: {}", e)))?;

        let mut keys_since_checkpoint = 0;

        while !self.checkpoint.is_complete() {
            let chunk_count = self.checkpoint.remaining().min(self.chunk_size);
            
            let keys = FastKeyGenerator::new(chunk_count)
                .parallel(self.parallel)
                .generate();

            // Write keys to file
            for key in &keys {
                writeln!(file, "{}", key.to_hex())
                    .map_err(|e| BatchError::io_error(format!("Failed to write key: {}", e)))?;
            }

            // Update checkpoint
            let last_key = keys.last().map(|k| k.to_hex());
            self.checkpoint.update(
                self.checkpoint.generated_count + keys.len(),
                last_key,
            );

            keys_since_checkpoint += keys.len();

            // Save checkpoint periodically
            if keys_since_checkpoint >= self.checkpoint_interval {
                self.checkpoint.save(&self.checkpoint_path)?;
                keys_since_checkpoint = 0;
            }

            // Report progress
            progress_callback(self.checkpoint.progress_percent());
        }

        // Final checkpoint save
        self.checkpoint.save(&self.checkpoint_path)?;

        Ok(self.checkpoint.generated_count)
    }

    /// Generate keys without progress callback.
    pub fn generate(&mut self) -> Result<usize, BatchError> {
        self.generate_with_progress(|_| {})
    }

    /// Clean up checkpoint file after successful completion.
    pub fn cleanup(&self) -> Result<(), BatchError> {
        Checkpoint::delete(&self.checkpoint_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_checkpoint_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("checkpoint.json");

        let mut checkpoint = Checkpoint::new_random("test-job", 1000, "output.txt");
        checkpoint.update(500, Some("abc123".to_string()));
        checkpoint.save(&path).unwrap();

        let loaded = Checkpoint::load(&path).unwrap();
        assert_eq!(loaded.job_id, "test-job");
        assert_eq!(loaded.total_count, 1000);
        assert_eq!(loaded.generated_count, 500);
        assert_eq!(loaded.last_key, Some("abc123".to_string()));
    }

    #[test]
    fn test_checkpoint_progress() {
        let mut checkpoint = Checkpoint::new_random("test", 1000, "out.txt");
        assert_eq!(checkpoint.progress_percent(), 0.0);
        assert_eq!(checkpoint.remaining(), 1000);
        assert!(!checkpoint.is_complete());

        checkpoint.update(500, None);
        assert_eq!(checkpoint.progress_percent(), 50.0);
        assert_eq!(checkpoint.remaining(), 500);

        checkpoint.update(1000, None);
        assert_eq!(checkpoint.progress_percent(), 100.0);
        assert!(checkpoint.is_complete());
    }

    #[test]
    fn test_resumable_generator() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("keys.txt");
        let checkpoint_path = dir.path().join("checkpoint.json");

        let mut generator = ResumableBatchGenerator::new(
            "test-job",
            100,
            output_path.to_str().unwrap(),
            checkpoint_path.to_str().unwrap(),
        )
        .chunk_size(10)
        .checkpoint_interval(50);

        let count = generator.generate().unwrap();
        assert_eq!(count, 100);

        // Verify output
        let content = std::fs::read_to_string(&output_path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 100);

        // Cleanup
        generator.cleanup().unwrap();
        assert!(!checkpoint_path.exists());
    }

    #[test]
    fn test_incremental_checkpoint() {
        let checkpoint = Checkpoint::new_incremental(
            "inc-job",
            1000,
            "output.txt",
            "0000000000000000000000000000000000000000000000000000000000000001",
        );

        assert_eq!(checkpoint.mode, GenerationMode::Incremental);
        assert!(checkpoint.start_key.is_some());
    }
}
