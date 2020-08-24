# Verifiable Remote Paper Voting
An implementation of a verifiable remote-voting protocol with paper assurance. Protocol by Xavier Boyen, Kristian Gjøsteen, Thomas Haines, Eleanor McMurtry, and Vanessa Teague.

To build and run, there is a makefile `make` (or run `cargo build --release --all --all-targets`).

k-out-of-n threshold ElGamal encryption is done with [Cryptid](https://github.com/eleanor-em/cryptid) using Pedersen secret sharing and Curve25519 ([Ristretto](https://ristretto.group/) subgroup).

## Building
1. Install `rustup` with the nightly toolchain using the installation script here: [download link](https://rustup.rs/).
 **Don't use a package manager to do this!**
    1. You'll need to select the custom installation settings to set it to use nightly. Otherwise, you can run `rustup install nightly` to switch to the right toolchain. 
1. Run `make`.
    1. You may need to install `libssl-dev` and `pkg-config` depending on the operating system.

## Running
**As a voter:** Run `target/release/voter`. It will generate two files: `paper1.pdf` and `paper2.pdf`. Print both.
Fold `paper1.pdf` so it hides the data, and fold `paper2.pdf` so it shows the data. Place both in an envelope and mail it.

**As the WBB:** Run `target/release/wbb`. To change the port it listens on, use `export ROCKET_PORT=xxxx`.

**As a trustee:** For the *leader* (who organises the other trustees), run `target/release/trustee leader <id> <addr1> <addr2> ...`
where the addresses are those of the follower, and `id` ranges from 1 to `n`. The other trustees should run `target/release/trustee follower <id> <port>`
where the port is that which you would like to listen on, matching the address the leader uses. The IDs should be such
that there is one of each from 1 to `n`.
