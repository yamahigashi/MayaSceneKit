fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let rc_file = std::path::Path::new("resources/windows/app.rc");
    let icon_file = std::path::Path::new("resources/windows/app.ico");
    println!("cargo:rerun-if-changed={}", rc_file.display());
    println!("cargo:rerun-if-changed={}", icon_file.display());

    match embed_resource::compile(rc_file, embed_resource::NONE) {
        embed_resource::CompilationResult::Ok | embed_resource::CompilationResult::NotWindows => {}
        other => panic!("failed to compile Windows resources: {other}"),
    }
}
