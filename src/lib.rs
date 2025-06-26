//! minivault is a local-only, light-weight encryption as a service.

#![doc = include_str!("../DOCS.md")]

/// Use minivault client functionality.
pub mod client;
/// Host and interact with a local minivault server.
pub mod server;
/// Work with the minivault Vault data.
pub mod vault;
