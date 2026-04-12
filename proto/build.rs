use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    
    // Compile audit.proto
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&out_dir)
        .compile(&["src/audit.proto"], &["src"])?;
    
    // Rename the generated file for audit
    let audit_generated = out_dir.join("axiomguard.v1.rs");
    let audit_renamed = out_dir.join("audit.rs");
    if audit_generated.exists() {
        std::fs::rename(&audit_generated, &audit_renamed)?;
    }
    
    // Compile shield.proto
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&out_dir)
        .compile(&["src/shield.proto"], &["src"])?;
    
    // The shield proto should generate a different file name due to different package
    // but let's ensure it's named correctly
    let shield_generated = out_dir.join("axiomguard.shield.v1.rs");
    let shield_renamed = out_dir.join("shield.rs");
    if shield_generated.exists() {
        std::fs::rename(&shield_generated, &shield_renamed)?;
    }
    
    Ok(())
}
