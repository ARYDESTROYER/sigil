//! Tauri's build script: generates the capability/permission schemas and the
//! platform metadata from `tauri.conf.json`.
fn main() {
    tauri_build::build();
}
