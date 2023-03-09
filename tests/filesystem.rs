#![cfg(feature = "virt")]

use trussed::{
    client::{CryptoClient, FilesystemClient},
    error::Error,
    syscall, try_syscall,
    types::{Bytes, Location, Mechanism, PathBuf, StorageAttributes},
};

mod client;

#[test]
fn escape_namespace_parent() {
    client::get(|client| {
        let key = syscall!(client.generate_key(Mechanism::P256, StorageAttributes::new())).key;

        // first approach: directly escape namespace
        let mut path = PathBuf::from("..");
        path.push(&PathBuf::from("sec"));
        path.push(&PathBuf::from(key.hex().as_slice()));
        assert_eq!(
            try_syscall!(client.read_file(Location::Volatile, path)),
            Err(Error::InvalidPath),
        );

        // second approach: start with subdir, then escape namespace
        let mut path = PathBuf::from("foobar/../..");
        path.push(&PathBuf::from("sec"));
        path.push(&PathBuf::from(key.hex().as_slice()));
        assert_eq!(
            try_syscall!(client.read_file(Location::Volatile, path)),
            Err(Error::InvalidPath),
        );

        // false positive: does not escape namespace but still forbidden
        let mut path = PathBuf::from("foobar/..");
        path.push(&PathBuf::from("sec"));
        path.push(&PathBuf::from(key.hex().as_slice()));
        assert_eq!(
            try_syscall!(client.read_file(Location::Volatile, path)),
            Err(Error::InvalidPath),
        );
    })
}

#[test]
fn escape_namespace_root() {
    client::get(|client| {
        let key = syscall!(client.generate_key(Mechanism::P256, StorageAttributes::new())).key;
        let mut path = PathBuf::from("/test");
        path.push(&PathBuf::from("sec"));
        path.push(&PathBuf::from(key.hex().as_slice()));
        assert!(try_syscall!(client.read_file(Location::Volatile, path)).is_err());
    })
}

fn iterating(location: Location) {
    client::get(|client| {
        syscall!(client.write_file(
            location,
            PathBuf::from("foo"),
            Bytes::from_slice(b"foo").unwrap(),
            None
        ));
        syscall!(client.write_file(
            location,
            PathBuf::from("bar"),
            Bytes::from_slice(b"bar").unwrap(),
            None
        ));
        let first_entry = syscall!(client.read_dir_first(location, PathBuf::from(""), None))
            .entry
            .unwrap();
        assert_eq!(first_entry.file_name(), "bar");

        let next_entry = syscall!(client.read_dir_next()).entry.unwrap();
        assert_eq!(next_entry.file_name(), "foo");

        let first_data = syscall!(client.read_dir_files_first(location, PathBuf::from(""), None))
            .data
            .unwrap();
        assert_eq!(first_data, b"bar");
        let next_data = syscall!(client.read_dir_files_next()).data.unwrap();
        assert_eq!(next_data, b"foo");
    });
}

#[test]
fn iterating_internal() {
    iterating(Location::Internal);
}
#[test]
fn iterating_external() {
    iterating(Location::External);
}
#[test]
fn iterating_volatile() {
    iterating(Location::Volatile);
}
