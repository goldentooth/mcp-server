use aws_config::BehaviorVersion;
use aws_sdk_bedrockruntime::{Client as BedrockRuntimeClient, primitives::Blob};
use aws_sdk_s3::Client as S3Client;
use serde_json::{Value, json};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VectorError {
    #[error("AWS configuration error: {0}")]
    AwsConfig(String),
    #[error("S3 operation failed: {0}")]
    S3Operation(String),
    #[error("Bedrock operation failed: {0}")]
    BedrockOperation(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid vector data: {0}")]
    InvalidVector(String),
}

impl VectorError {
    /// Convert to MCP ErrorData for protocol responses
    pub fn to_error_data(&self) -> rmcp::model::ErrorData {
        use rmcp::model::ErrorCode;

        match self {
            VectorError::AwsConfig(msg) => rmcp::model::ErrorData {
                code: ErrorCode(-32007),
                message: format!("AWS configuration error: {msg}").into(),
                data: Some(serde_json::json!({
                    "error_type": "aws_config",
                    "details": msg
                })),
            },
            VectorError::S3Operation(msg) => rmcp::model::ErrorData {
                code: ErrorCode(-32008),
                message: format!("S3 operation failed: {msg}").into(),
                data: Some(serde_json::json!({
                    "error_type": "s3_operation",
                    "details": msg
                })),
            },
            VectorError::BedrockOperation(msg) => rmcp::model::ErrorData {
                code: ErrorCode(-32009),
                message: format!("Bedrock operation failed: {msg}").into(),
                data: Some(serde_json::json!({
                    "error_type": "bedrock_operation",
                    "details": msg
                })),
            },
            VectorError::Serialization(err) => rmcp::model::ErrorData {
                code: ErrorCode(-32004), // Reuse serialization error code
                message: format!("Vector data serialization failed: {err}").into(),
                data: Some(serde_json::json!({
                    "error_type": "serialization",
                    "details": err.to_string()
                })),
            },
            VectorError::InvalidVector(msg) => rmcp::model::ErrorData {
                code: ErrorCode(-32010),
                message: format!("Invalid vector data: {msg}").into(),
                data: Some(serde_json::json!({
                    "error_type": "invalid_vector",
                    "details": msg
                })),
            },
        }
    }
}

pub type VectorResult<T> = Result<T, VectorError>;

/// Vector operations for storing and searching cluster knowledge
#[derive(Debug, Clone)]
pub struct VectorService {
    s3_client: S3Client,
    bedrock_runtime: BedrockRuntimeClient,
    bucket_name: String,
    index_name: String,
}

impl VectorService {
    /// Create a new VectorService instance
    pub async fn new(bucket_name: String, index_name: String) -> VectorResult<Self> {
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;

        // Validate AWS credentials are available
        if config.credentials_provider().is_none() {
            return Err(VectorError::AwsConfig(
                "No AWS credentials found. Please configure AWS credentials.".to_string(),
            ));
        }

        let s3_client = S3Client::new(&config);
        let bedrock_runtime = BedrockRuntimeClient::new(&config);

        Ok(VectorService {
            s3_client,
            bedrock_runtime,
            bucket_name,
            index_name,
        })
    }

    /// Generate embeddings for text using AWS Bedrock
    async fn generate_embedding(&self, text: &str) -> VectorResult<Vec<f32>> {
        // Use Cohere Embed English v3 model
        let model_id = "cohere.embed-english-v3";

        // Prepare the input for Cohere embedding model
        let input_data = json!({
            "texts": [text],
            "input_type": "search_document"
        });

        let request = self
            .bedrock_runtime
            .invoke_model()
            .model_id(model_id)
            .body(Blob::new(input_data.to_string()));

        let response = request.send().await.map_err(|e| {
            VectorError::BedrockOperation(format!("Failed to generate embedding: {e}"))
        })?;

        let response_body = response.body.as_ref();
        let response_json: Value =
            serde_json::from_slice(response_body).map_err(VectorError::Serialization)?;

        // Extract embeddings from Cohere response
        let embeddings = response_json
            .get("embeddings")
            .and_then(|e| e.as_array())
            .and_then(|arr| arr.first())
            .and_then(|emb| emb.as_array())
            .ok_or_else(|| VectorError::InvalidVector("No embeddings in response".to_string()))?;

        let embedding_vec: Result<Vec<f32>, _> = embeddings
            .iter()
            .map(|v| {
                v.as_f64().map(|f| f as f32).ok_or_else(|| {
                    VectorError::InvalidVector("Invalid embedding value".to_string())
                })
            })
            .collect();

        embedding_vec
    }

    /// Store cluster knowledge as vectors with metadata
    pub async fn store_knowledge(&self, documents: Vec<ClusterDocument>) -> VectorResult<Value> {
        let mut stored_count = 0;
        let mut errors = Vec::new();
        let total_documents = documents.len();

        for doc in documents {
            // Generate embedding for the document content
            let embedding = match self.generate_embedding(&doc.content).await {
                Ok(emb) => emb,
                Err(e) => {
                    errors.push(format!("Failed to generate embedding: {e}"));
                    continue;
                }
            };

            // Create a unique key for this document
            let doc_id = format!("{}-{}", doc.timestamp.timestamp(), doc.content.len());
            let key = format!("{}/{}.json", self.index_name, doc_id);

            // Prepare document with embedding for storage
            let doc_with_embedding = json!({
                "content": doc.content,
                "data_type": doc.data_type,
                "metadata": doc.metadata,
                "timestamp": doc.timestamp.to_rfc3339(),
                "embedding": embedding,
                "embedding_model": "cohere.embed-english-v3"
            });

            // Store in S3
            let result = self
                .s3_client
                .put_object()
                .bucket(&self.bucket_name)
                .key(&key)
                .body(aws_sdk_s3::primitives::ByteStream::from(
                    doc_with_embedding.to_string().into_bytes(),
                ))
                .content_type("application/json")
                .send()
                .await;

            match result {
                Ok(_) => stored_count += 1,
                Err(e) => errors.push(format!("Failed to store document {doc_id}: {e}")),
            }
        }

        Ok(json!({
            "success": errors.is_empty(),
            "stored_count": stored_count,
            "total_documents": total_documents,
            "errors": if errors.is_empty() { Value::Null } else { json!(errors) },
            "operation": "store_knowledge"
        }))
    }

    /// Calculate cosine similarity between two vectors
    fn cosine_similarity(&self, vec_a: &[f32], vec_b: &[f32]) -> f32 {
        if vec_a.len() != vec_b.len() {
            return 0.0;
        }

        let dot_product: f32 = vec_a.iter().zip(vec_b.iter()).map(|(a, b)| a * b).sum();
        let norm_a: f32 = vec_a.iter().map(|a| a * a).sum::<f32>().sqrt();
        let norm_b: f32 = vec_b.iter().map(|b| b * b).sum::<f32>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            dot_product / (norm_a * norm_b)
        }
    }
    /// Search for relevant cluster knowledge using vector similarity
    pub async fn search_knowledge(
        &self,
        query: &str,
        limit: Option<u32>,
        metadata_filters: Option<HashMap<String, String>>,
    ) -> VectorResult<Value> {
        let limit = limit.unwrap_or(10) as usize;

        // Generate embedding for the query
        let query_embedding = self.generate_embedding(query).await?;

        // List all documents in the index
        let list_response = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket_name)
            .prefix(format!("{}/", self.index_name))
            .send()
            .await
            .map_err(|e| VectorError::S3Operation(format!("Failed to list objects: {e}")))?;

        let mut candidates = Vec::new();

        // Process each document
        if let Some(objects) = list_response.contents {
            for object in objects {
                if let Some(key) = object.key {
                    // Retrieve document
                    let get_response = self
                        .s3_client
                        .get_object()
                        .bucket(&self.bucket_name)
                        .key(&key)
                        .send()
                        .await;

                    let document_data = match get_response {
                        Ok(response) => {
                            let bytes = response.body.collect().await.map_err(|e| {
                                VectorError::S3Operation(format!("Failed to read object body: {e}"))
                            })?;
                            bytes.into_bytes()
                        }
                        Err(_) => continue, // Skip documents that can't be read
                    };

                    // Parse document JSON
                    let doc_json: Value = match serde_json::from_slice(&document_data) {
                        Ok(json) => json,
                        Err(_) => continue, // Skip malformed documents
                    };

                    // Extract embedding
                    let doc_embedding: Vec<f32> = match doc_json.get("embedding") {
                        Some(emb_val) => match emb_val.as_array() {
                            Some(arr) => {
                                let emb_result: Result<Vec<f32>, _> = arr
                                    .iter()
                                    .map(|v| {
                                        v.as_f64().map(|f| f as f32).ok_or("Invalid embedding")
                                    })
                                    .collect();
                                match emb_result {
                                    Ok(emb) => emb,
                                    Err(_) => continue,
                                }
                            }
                            None => continue,
                        },
                        None => continue,
                    };

                    // Apply metadata filters if specified
                    if let Some(filters) = &metadata_filters {
                        if let Some(doc_metadata) =
                            doc_json.get("metadata").and_then(|m| m.as_object())
                        {
                            let mut matches_all_filters = true;
                            for (filter_key, filter_value) in filters {
                                if !doc_metadata
                                    .get(filter_key)
                                    .and_then(|v| v.as_str())
                                    .map(|v| v == filter_value)
                                    .unwrap_or(false)
                                {
                                    matches_all_filters = false;
                                    break;
                                }
                            }
                            if !matches_all_filters {
                                continue;
                            }
                        } else {
                            continue; // Skip if no metadata but filters specified
                        }
                    }

                    // Calculate similarity
                    let similarity = self.cosine_similarity(&query_embedding, &doc_embedding);

                    candidates.push(json!({
                        "content": doc_json.get("content").unwrap_or(&Value::Null),
                        "data_type": doc_json.get("data_type").unwrap_or(&Value::Null),
                        "metadata": doc_json.get("metadata").unwrap_or(&json!({})),
                        "timestamp": doc_json.get("timestamp").unwrap_or(&Value::Null),
                        "similarity_score": similarity,
                        "document_id": key
                    }));
                }
            }
        }

        // Sort by similarity score (highest first)
        candidates.sort_by(|a, b| {
            let score_a = a
                .get("similarity_score")
                .and_then(|s| s.as_f64())
                .unwrap_or(0.0);
            let score_b = b
                .get("similarity_score")
                .and_then(|s| s.as_f64())
                .unwrap_or(0.0);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Take top results
        candidates.truncate(limit);

        Ok(json!({
            "success": true,
            "query": query,
            "results": candidates,
            "total_found": candidates.len(),
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
