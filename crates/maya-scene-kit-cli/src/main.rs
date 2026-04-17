pub(crate) mod scene;
mod cli;

fn main() {
    std::process::exit(cli::main(std::env::args().skip(1).collect()));
}
