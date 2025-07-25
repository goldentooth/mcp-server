use rmcp::model::ProtocolVersion;

fn main() {
    println!("Testing ProtocolVersion construction:");

    // Check if we can create a ProtocolVersion from a string
    let version_str = "0.1.0";

    // See if we can construct it directly (this may not work)
    println!("Trying to create version: {}", version_str);

    // Let's see what methods are available on ProtocolVersion
    let default_version = ProtocolVersion::V_2024_11_05;
    println!("Default version: {:?}", default_version);

    // Check if there are any other variants available
    // Let's try some that might exist

    // See if we can access the inner string
    println!("Version as string: {}", format!("{:?}", default_version));
}
