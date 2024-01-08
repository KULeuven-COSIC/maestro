mod share;
mod party;
mod network;
mod dec;
mod chida;

use std::{path::PathBuf, time::Duration};

use clap::{Parser, Subcommand};
use network::ConnectedParty;

#[derive(Parser)]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    ChidaBenchmark {
        #[arg(long)]
        simd: usize
    }
}

fn main() {
    let cli = Cli::parse();

    let (party_index, config) = network::Config::from_file(&cli.config).unwrap();

    match cli.command {
        Commands::ChidaBenchmark { simd } => {
            let connected = ConnectedParty::bind_and_connect(party_index, config, Some(Duration::from_secs_f32(1.0))).unwrap();
            println!("Connected!");
            chida::chida_benchmark(connected, simd);
        }
    }
}
