//! KeyVault — núcleo de domínio, criptografia, formato e persistência (sem dependência de Tauri).
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod crypto;
pub mod envelope;
pub mod error;
pub mod fsutil;
pub mod generator;
pub mod limits;
pub mod model;
pub mod payload;
pub mod rng;
pub mod secret;
pub mod service;
pub mod storage;

pub use error::{CoreError, Field, FormatError, Result};
