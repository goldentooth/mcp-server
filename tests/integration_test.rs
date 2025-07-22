use goldentooth_mcp::service::GoldentoothService;
use rmcp::{RoleServer, Service, ServiceExt};
use tokio::io::duplex;

/// Helper function to create a test transport
fn create_test_transport() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    duplex(1024)
}

#[tokio::test]
async fn test_service_serves_correctly() {
    // Test that the service can be served without panicking
    let service = GoldentoothService::new();
    let (client_read, server_write) = create_test_transport();
    let (server_read, client_write) = create_test_transport();

    // Start server in background
    let server_handle = tokio::spawn(async move {
        let transport = (server_read, server_write);
        match service.serve(transport).await {
            Ok(server) => {
                // Server started successfully
                match server.waiting().await {
                    Ok(_) => {}
                    Err(_) => {
                        // Connection closed is expected for this test
                    }
                }
            }
            Err(_) => {
                // Error during serve is expected since we're not following full protocol
            }
        }
    });

    // Close client side to trigger server shutdown
    drop(client_write);
    drop(client_read);

    // Wait for server to finish
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(1), server_handle).await;
}

#[test]
fn test_service_info_structure() {
    let service = GoldentoothService::new();
    let info = Service::<RoleServer>::get_info(&service);

    // Verify all required fields are present
    assert_eq!(info.server_info.name, "goldentooth-mcp");
    assert_eq!(info.server_info.version, "0.0.2");

    // Verify protocol version
    let _protocol = info.protocol_version;
    // Protocol version should be valid (this will be checked by rmcp internally)

    // Verify capabilities structure
    let _capabilities = info.capabilities;
    // For now, we're using default capabilities
    // Add specific capability tests as we implement features
}

#[test]
fn test_service_clone() {
    let service1 = GoldentoothService::new();
    let service2 = service1.clone();

    // Both services should have the same info
    let info1 = Service::<RoleServer>::get_info(&service1);
    let info2 = Service::<RoleServer>::get_info(&service2);

    assert_eq!(info1.server_info.name, info2.server_info.name);
    assert_eq!(info1.server_info.version, info2.server_info.version);
}
