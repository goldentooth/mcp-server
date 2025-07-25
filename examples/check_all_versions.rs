use rmcp::model::ProtocolVersion;

fn main() {
    println!("Checking all available ProtocolVersion variants:");

    // Try all the variants that might exist
    println!("V_2024_11_05: {:?}", ProtocolVersion::V_2024_11_05);

    // Maybe there are others? Let's see what happens if we try some common patterns
    // These will cause compilation errors if they don't exist

    // Try some that might exist for older versions
    // (This is just to see what's available - will fail to compile if they don't exist)
}
