use std::error::Error;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let output_dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: auditbase-export-schemas <output-directory>")?;
    fs::create_dir_all(&output_dir)?;

    for (filename, schema) in codex_auditbase_contract::generated_schemas() {
        let mut encoded = serde_json::to_string_pretty(&schema)?;
        encoded.push('\n');
        fs::write(output_dir.join(filename), encoded)?;
    }
    Ok(())
}
