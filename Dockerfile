FROM rustlang/rust:nightly

WORKDIR /usr/src/app
COPY common common
COPY src src
COPY trustee trustee
COPY voter voter
COPY wbb wbb
COPY Cargo.toml .
COPY Makefile .
COPY candidates.json .

RUN cd voter && cargo build --release

CMD [ "./target/release/voter" ]
