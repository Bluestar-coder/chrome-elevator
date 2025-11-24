// Chrome Elevator - Rust Edition Library
// Exports modules for use in integration tests and external consumers

pub mod decryption;
pub mod ffi;
pub mod injection;
pub mod obfuscation;

// Re-export commonly used types
pub use decryption::{AbeDecryptor, BrowserConfig, DataExtractor, ExtractionResult};
pub use ffi::*;
pub use injection::*;
pub use obfuscation::*;
