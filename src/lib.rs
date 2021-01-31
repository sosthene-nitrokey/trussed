#![cfg_attr(not(test), no_std)]
// #![no_std]

// prevent a spurious error message: https://github.com/rust-lang/rust/issues/54010
// UNFORTUNATELY: with #![cfg(test)], no longer compiles for no_std,
// with #[cfg(test)] error still shown
// #[cfg(test)]
// extern crate std;

#[macro_use]
extern crate delog;
generate_macros!();

#[cfg(not(any(
    feature = "clients-1",
    feature = "clients-2",
    feature = "clients-3",
    feature = "clients-4",
    feature = "clients-5",
    feature = "clients-6",
    feature = "clients-7",
    feature = "clients-8",
    feature = "clients-9",
    feature = "clients-10",
    feature = "clients-11",
    feature = "clients-12",
)))]
compile_error!("Please select how many Trussed™ clients will be needed, using one of the `clients-*` features.");

pub use interchange::Interchange;

pub mod api;
pub mod client;
pub mod config;
pub mod error;
pub mod mechanisms;
pub mod pipe;
pub mod platform;
pub mod service;
pub mod store;
pub mod types;

pub use api::Reply;
pub use error::Error;
pub use client::{Client, ClientImplementation};
pub use service::Service;

pub use cbor_smol::{cbor_serialize, cbor_serialize_bytes, cbor_serialize_bytebuf, cbor_deserialize};
pub use heapless_bytes::{ArrayLength, Bytes as ByteBuf, consts};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[macro_use]
extern crate serial_test;

