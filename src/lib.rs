#![feature(untagged_unions)]
use std::fmt;
use std::io;
use nix;


mod bytes;
pub mod packet;
pub mod tuntap;


#[derive(Clone, Debug)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.0)
    }
}

impl From<io::Error> for Error {
    fn from(x: io::Error) -> Error { Error(x.to_string()) }
}

impl From<nix::Error> for Error {
    fn from(x: nix::Error) -> Error { Error(x.to_string()) }
}

impl<'a> From<&'a str> for Error {
    fn from(x: &'a str) -> Error { Error(x.to_owned()) }
}

pub trait ErrorAt<T> {
    fn at(self, at: &str) -> Result<T, Error>;
}

impl<T, E: Into<Error>> ErrorAt<T> for Result<T, E> {
    fn at(self, at: &str) -> Result<T, Error> {
        self.map_err(|e| Error(format!("{}: {}", at, e.into())))
    }
}
