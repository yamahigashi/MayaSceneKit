fn main() {
    std::process::exit(maya_scene_kit::cli::main(
        std::env::args().skip(1).collect(),
    ));
}
