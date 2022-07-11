# Verifiable Remote Paper Voting
An implementation of a verifiable remote-voting protocol with paper assurance. Protocol by Xavier Boyen, Kristian Gjøsteen, Thomas Haines, Eleanor McMurtry, and Vanessa Teague.

## This code is for academic purposes ONLY. DO NOT USE IT IN PRACTICE.

To build and run, there is a makefile `make` (or run `cargo build --release --all --all-targets`).

k-out-of-n threshold ElGamal encryption is done with [Cryptid](https://github.com/eleanor-em/cryptid) using Pedersen secret sharing and Curve25519 ([Ristretto](https://ristretto.group/) subgroup).

## Building & Running
### Run via Docker
If you'd like to use Docker, there is a Dockerfile provided for the voter interface. (TODO: Dockerfiles for the other stuff?)
1. Run `docker build -t papervote .` to build the image.
1. Run `docker run -it --name voter papervote` to run the image, and make your selections.
1. Run the following commands to copy the printable PDF output:
    1. `docker cp voter:/usr/src/app/paper1.pdf .`
    1. `docker cp voter:/usr/src/app/paper2.pdf .`

### Building
1. Install `rustup` with the nightly toolchain using the installation script here: [download link](https://rustup.rs/).
 **Don't use a package manager to do this!**
    1. You'll need to select the custom installation settings to set it to use nightly. Otherwise, you can run `rustup install nightly` to install the right toolchain, then `rustup default nightly` to set it as your default. 
1. Run `make`.
    1. You may need to install `libssl-dev` and `pkg-config` depending on the operating system.

### Running
**As a voter:** Run `target/release/voter`. It will generate two files: `paper1.pdf` and `paper2.pdf`. Print both.
Fold `paper1.pdf` so it hides the data, and fold `paper2.pdf` so it shows the data. Place both in an envelope and mail it. **Note:** if `debug_mode = true` in `~/.config/papervote/papervote.toml`, then this will also produce a file `raw.txt` that can be piped into the receiving binary for ease of testing.

**Verifying:** Run `target/release/verify` and enter the voter ID to check for that voter ID's presence. Run `target/release/verify all` to run the global verifier, checking that all the proofs are valid and the facts on the WBB have been correctly checked.

**As the WBB:** Run `target/release/wbb`. To change the port it listens on, use `export ROCKET_PORT=xxxx`.

**As a trustee:** For the *leader* (who organises the other trustees), run `target/release/trustee leader <id> <addr1> <addr2> ...`
where the addresses are those of the follower, and `id` ranges from 1 to `n`. The other trustees should run `target/release/trustee follower <id> <port>`
where the port is that which you would like to listen on, matching the address the leader uses. The IDs should be such
that there is one of each from 1 to `n`.

**Receiving votes:** Run `target/release/trustee receive <leader address>` to receive a vote interactively. Votes are encoded in base-36 in the order they appear on the ballot, starting from 0. For example, a ballot reading `Alice: 2 Bob: 3 Eve: 1` would be encoded as `120`; this is the encoding that must be entered when prompted for a vote. 
