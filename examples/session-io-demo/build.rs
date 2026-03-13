use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=input/message.txt");

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should exist"));
    let message_path = manifest_dir.join("input/message.txt");
    let message = fs::read_to_string(&message_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", message_path.display()));

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR should exist"));
    let generated = out_dir.join("generated_message.rs");
    let generated_body = format!(
        "pub const GENERATED_MESSAGE: &str = {:?};\n",
        message.trim_end()
    );

    fs::write(&generated, generated_body)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", generated.display()));
}
