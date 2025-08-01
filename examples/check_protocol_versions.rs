use rmcp::model::ProtocolVersion;

fn main() {
    println!("Available ProtocolVersion variants:");

    // Try to print debug representation of different versions
    println!("V_2024_11_05: {:?}", ProtocolVersion::V_2024_11_05);

    // Check if there are other variants by trying to access them
    // This will compile if they exist, otherwise will fail compilation

    // Let's see what the Debug representation shows
    println!("String representation: {:?}", ProtocolVersion::V_2024_11_05);

    // Also check if we can create from string
    // (this might not be implemented but worth checking)
}
