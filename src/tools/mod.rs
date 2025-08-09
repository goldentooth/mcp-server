use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::HashMap;

#[async_trait]
pub trait McpTool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn input_schema(&self) -> Value;
    async fn execute(&self, params: Value) -> Result<Value, String>;
}

pub struct ClusterPingTool;

#[async_trait]
impl McpTool for ClusterPingTool {
    fn name(&self) -> &str {
        "cluster_ping"
    }

    fn description(&self) -> &str {
        "Ping all nodes in the Goldentooth cluster to check connectivity"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "node": {
                    "type": "string",
                    "description": "Specific node to ping (optional, defaults to all nodes)"
                }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, _params: Value) -> Result<Value, String> {
        // Minimal implementation that returns mock results
        let mut nodes = HashMap::new();
        nodes.insert(
            "allyrion",
            json!({
                "status": "reachable",
                "ping_time_ms": 1.2
            }),
        );

        Ok(json!({
            "nodes": nodes
        }))
    }
}

pub fn get_all_tools() -> Vec<Box<dyn McpTool>> {
    vec![Box::new(ClusterPingTool)]
}

pub async fn execute_tool(name: &str, params: Value) -> Result<Value, String> {
    let tools = get_all_tools();

    for tool in tools {
        if tool.name() == name {
            return tool.execute(params).await;
        }
    }

    Err(format!("Tool '{name}' not found"))
}
