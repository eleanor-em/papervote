# Verifiable Remote Paper Voting
An implementation of a verifiable remote-voting protocol with paper assurance. Protocol by Xavier Boyen, Kristian Gjøsteen, Thomas Haines, Eleanor McMurtry, and Vanessa Teague.

To build and run, there is a makefile `make` (or run `cargo build --release --all --all-targets`).

k-out-of-n threshold ElGamal encryption is done with [Cryptid](https://github.com/eleanor-em/cryptid) using Pedersen secret sharing and Curve25519 ([Ristretto](https://ristretto.group/) subgroup).

## Building
1. Install `rustup` with the nightly configuration in custom installation settings ([Rust toolkit download link](https://rustup.rs/)).
1. Run `make`.
    1. You may need to install `libssl-dev` and `pkg-config` depending on the operating system.

## Running
**As a voter:** Run `target/release/voter`. The values listed as `Paper 1` should be printed onto one piece of paper,
and the values listed as `Paper 2` should be printed onto another piece of paper. Both of these should be placed into
the same envelope and mailed to the address.

**As the WBB:** Run `target/release/wbb`. To change the port it listens on, use `export ROCKET_PORT=xxxx`.

**As a trustee:** For the *leader* (who organises the other trustees), run `target/release/trustee leader <id> <addr1> <addr2> ...`
where the addresses are those of the follower, and `id` ranges from 1 to `n`. The other trustees should run `target/release/trustee follower <id> <port>`
where the port is that which you would like to listen on, matching the address the leader uses. The IDs should be such
that there is one of each from 1 to `n`.
