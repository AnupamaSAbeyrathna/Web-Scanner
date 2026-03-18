use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: String,
    pub target: String,
    pub status: ScanStatus,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanStatus { Pending, Running, Done }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub url: String,
    pub vulnerability: String,  // "XSS" | "MissingHeader"
    pub severity: String,       // "HIGH" | "MEDIUM" | "LOW"
    pub evidence: String,
}