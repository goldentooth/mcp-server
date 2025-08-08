use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Emit build-time information
    EmitBuilder::builder()
        .build_timestamp()
        .git_branch()
        .git_sha(true) // Short SHA
        .emit()?;

    Ok(())
}
