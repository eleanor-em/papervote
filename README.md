# Verifiable Remote Paper Voting
An implementation of a verifiable remote-voting protocol with paper assurance. Protocol by Xavier Boyen, Kristian Gjøsteen, Thomas Haines, Eleanor McMurtry, and Vanessa Teague.

To build and run, there is a makefile `make` (or run `cargo build --release --all --all-targets`).

k-out-of-n threshold ElGamal encryption is done with [Cryptid](https://github.com/eleanor-em/cryptid) using Pedersen secret sharing and Curve25519 ([Ristretto](https://ristretto.group/) subgroup).

## Building
1. Install `rustup` with the nightly configuration in custom installation settings ([Rust toolkit download link](https://rustup.rs/)).
1. Run `make`.
    1. You may need to install `libssl-dev` and `pkg-config` depending on the operating system.

## Running
(TODO)