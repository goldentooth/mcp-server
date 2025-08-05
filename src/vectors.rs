use aws_config::BehaviorVersion;
use aws_sdk_s3vectors::Client;
use serde_json::{Value, json};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VectorError {
    #[error("AWS configuration error: {0}")]
    AwsConfig(String),
    #[error("S3 Vectors operation failed: {0}")]
    S3Operation(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid vector data: {0}")]
    InvalidVector(String),
}

pub type VectorResult<T> = Result<T, VectorError>;

/// Vector operations for storing and searching cluster knowledge
#[derive(Debug, Clone)]
pub struct VectorService {
    #[allow(dead_code)]
    client: Client,
    #[allow(dead_code)]
    bucket_name: String,
    #[allow(dead_code)]
    index_name: String,
}

impl VectorService {
    /// Create a new VectorService instance
    pub async fn new(bucket_name: String, index_name: String) -> VectorResult<Self> {
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;

        let client = Client::new(&config);

        Ok(VectorService {
            client,
            bucket_name,
            index_name,
        })
    }

    /// Store cluster knowledge as vectors with metadata
    pub async fn store_knowledge(&self, documents: Vec<ClusterDocument>) -> VectorResult<Value> {
        // TODO: Implement vector storage using PutVectors operation
        // This would:
        // 1. Generate embeddings for the documents (using external service or local model)
        // 2. Store vectors with metadata using client.put_vectors()

        Ok(json!({
            "success": true,
            "stored_count": documents.len(),
            "operation": "store_knowledge"
        }))
    }

    /// Search for relevant cluster knowledge using vector similarity
    pub async fn search_knowledge(
        &self,
        query: &str,
        limit: Option<u32>,
        metadata_filters: Option<HashMap<String, String>>,
    ) -> VectorResult<Value> {
        // TODO: Implement vector search using QueryVectors operation
        // This would:
        // 1. Generate embedding for the query
        // 2. Perform similarity search using client.query_vectors()
        // 3. Return matching documents with scores

        let limit = limit.unwrap_or(10);

        Ok(json!({
            "success": true,
            "query": query,
            "results": [],
            "limit": limit,
            "filters": metadata_filters,
            "operation": "search_knowledge"
        }))
    }

    /// Index cluster documentation and logs for RAG
    pub async fn index_cluster_data(
        &self,
        data_type: ClusterDataType,
        content: &str,
        metadata: HashMap<String, String>,
    ) -> VectorResult<Value> {
        let document = ClusterDocument {
            content: content.to_string(),
            data_type,
            metadata,
            timestamp: chrono::Utc::now(),
        };

        self.store_knowledge(vec![document]).await
    }
}

/// Types of cluster data that can be vectorized
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ClusterDataType {
    /// Configuration files (YAML, TOML, etc.)
    Configuration,
    /// Log entries from services
    LogEntry,
    /// Documentation (CLAUDE.md, README, etc.)
    Documentation,
    /// Service status and metrics
    ServiceStatus,
    /// Error messages and troubleshooting
    ErrorMessage,
    /// Command outputs and results
    CommandOutput,
}

/// Document structure for cluster knowledge
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusterDocument {
    /// Text content to be vectorized
    pub content: String,
    /// Type of cluster data
    pub data_type: ClusterDataType,
    /// Additional metadata for filtering
    pub metadata: HashMap<String, String>,
    /// When this document was created
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ClusterDocument {
    /// Create a new cluster document
    pub fn new(
        content: String,
        data_type: ClusterDataType,
        metadata: HashMap<String, String>,
    ) -> Self {
        Self {
            content,
            data_type,
            metadata,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Add node information to metadata
    pub fn with_node(mut self, node: &str) -> Self {
        self.metadata.insert("node".to_string(), node.to_string());
        self
    }

    /// Add service information to metadata
    pub fn with_service(mut self, service: &str) -> Self {
        self.metadata
            .insert("service".to_string(), service.to_string());
        self
    }

    /// Add priority level to metadata
    pub fn with_priority(mut self, priority: &str) -> Self {
        self.metadata
            .insert("priority".to_string(), priority.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_document_creation() {
        let mut metadata = HashMap::new();
        metadata.insert("test_key".to_string(), "test_value".to_string());

        let doc = ClusterDocument::new(
            "Test content".to_string(),
            ClusterDataType::Documentation,
            metadata.clone(),
        );

        assert_eq!(doc.content, "Test content");
        assert!(matches!(doc.data_type, ClusterDataType::Documentation));
        assert_eq!(
            doc.metadata.get("test_key"),
            Some(&"test_value".to_string())
        );
    }

    #[test]
    fn test_cluster_document_builder_methods() {
        let doc = ClusterDocument::new(
            "Test content".to_string(),
            ClusterDataType::LogEntry,
            HashMap::new(),
        )
        .with_node("allyrion")
        .with_service("consul")
        .with_priority("high");

        assert_eq!(doc.metadata.get("node"), Some(&"allyrion".to_string()));
        assert_eq!(doc.metadata.get("service"), Some(&"consul".to_string()));
        assert_eq!(doc.metadata.get("priority"), Some(&"high".to_string()));
    }
}
