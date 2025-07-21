use rmcp::{
    Service, ServiceExt, RoleServer,
    service::{ServiceRole, RequestContext, NotificationContext},
    model::{ErrorData, InitializeResult, Implementation, ServerCapabilities, ProtocolVersion}
};
use tokio::io::{stdin, stdout};
use std::future::Future;

#[derive(Clone)]
struct GoldentoothService;

impl GoldentoothService {
    fn new() -> Self {
        GoldentoothService
    }
}

impl Service<RoleServer> for GoldentoothService {
    fn handle_request(
        &self,
        _request: <RoleServer as ServiceRole>::PeerReq,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<<RoleServer as ServiceRole>::Resp, ErrorData>> + Send + '_ {
        async move {
            // For now, just return a generic error
            // We'll implement proper request handling later
            unimplemented!("Request handling not yet implemented")
        }
    }

    fn handle_notification(
        &self,
        _notification: <RoleServer as ServiceRole>::PeerNot,
        _context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + Send + '_ {
        async move {
            Ok(())
        }
    }

    fn get_info(&self) -> <RoleServer as ServiceRole>::Info {
        InitializeResult {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::default(),
            server_info: Implementation {
                name: "goldentooth-mcp".to_string(),
                version: "0.1.0".to_string(),
            },
            instructions: None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = (stdin(), stdout());
    
    let service = GoldentoothService::new();
    
    let server = service.serve(transport).await?;
    
    let _quit_reason = server.waiting().await?;
    
    Ok(())
}
