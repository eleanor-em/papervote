use eyre::Result;
use itertools::Itertools;
use clap::{App, Arg, SubCommand};
use trustee::leader::run_leader;
use trustee::follower::run_follower;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new("Verifiable Vote-by-Mail: Trustee")
        .version("0.1")
        .author("Eleanor McMurtry <elmcmurtry1@gmail.com>")
        .about("Runs a trustee for the verifiable vote-by-mail protocol.")
        .subcommand(SubCommand::with_name("leader")
            .about("acts as a leader")
            .arg(Arg::with_name("INDEX")
                .help("This trustee's index, from 1-n.")
                .required(true)
                .index(1))
            .arg(Arg::with_name("addresses")
                .help("The addresses of other trustees.")
                .multiple(true)
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("follower")
            .about("acts as a follower")
            .arg(Arg::with_name("INDEX")
                .help("This trustee's index, from 1-n.")
                .required(true)
                .index(1))
            .arg(Arg::with_name("PORT")
                .help("The port to listen on.")
                .required(true)
                .index(2)))
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("leader") {
        let index = matches.value_of("INDEX")
            .map(|index| index.parse::<usize>());

        if let Some(Ok(index)) = index {
            if let Some(addresses) = matches.values_of("addresses") {
                run_leader(index, addresses.collect_vec()).await
            } else {
                eprintln!("Addresses missing.");
                Ok(())
            }
        } else {
            eprintln!("Index must be a valid integer.");
            Ok(())
        }
    } else if let Some(matches) = matches.subcommand_matches("follower") {
        let index = matches.value_of("INDEX")
            .map(|index| index.parse::<usize>());

        if let Some(Ok(index)) = index {
            let port = matches.value_of("PORT")
                .map(|port| port.parse::<u16>());

            if let Some(Ok(port)) = port {
                run_follower(index, port).await
            } else {
                eprintln!("Port must be a valid 16-bit integer.");
                Ok(())
            }
        } else {
            eprintln!("Index must be a valid integer.");
            Ok(())
        }
    } else {
        println!("Run `trustee --help` for information.");
        Ok(())
    }
}
