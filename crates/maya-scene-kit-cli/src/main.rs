mod cli;
pub(crate) mod scene;

fn main() {
    std::process::exit(cli::main(std::env::args().skip(1).collect()));
}
