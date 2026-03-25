use crate::model::{Finding, ScanJob, ScanStatus};
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::{HashSet, VecDeque, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

pub async fn run_scan(scan_id: String, target: String, db: Arc<Mutex<HashMap<String, ScanJob>>>) {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| Client::new());

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(target.clone());
    visited.insert(target.clone());

    let mut all_findings = Vec::new();

    // Simple crawler - limit to 10 pages for MVP
    let mut pages_crawled = 0;
    while let Some(url) = queue.pop_front() {
        if pages_crawled >= 10 {
            break;
        }
        pages_crawled += 1;

        println!("Scanning: {}", url);
        
        // --- 1. Basic Reflected XSS Check (URL Parameters) ---
        if url.contains('?') {
            check_reflected_xss(&client, &url, &mut all_findings).await;
        }

        match client.get(&url).send().await {
            Ok(response) => {
                println!("Got response {} for {}", response.status(), url);
                
                // --- 2. Security Headers Analysis ---
                let headers = response.headers();
                let missing_headers = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"];
                
                for header in missing_headers {
                    if !headers.contains_key(header) {
                        all_findings.push(Finding {
                            url: url.clone(),
                            vulnerability: "MissingHeader".to_string(),
                            severity: "LOW".to_string(),
                            evidence: format!("Missing security header: {}", header),
                        });
                    }
                }

                if let Ok(text) = response.text().await {
                    // --- 3. Parse Links for Crawler ---
                    let document = Html::parse_document(&text);
                    if let Ok(selector) = Selector::parse("a") {
                        for element in document.select(&selector) {
                            if let Some(href) = element.value().attr("href") {
                                // Basic URL normalization
                                if href.starts_with(&target) && !visited.contains(href) {
                                    visited.insert(href.to_string());
                                    queue.push_back(href.to_string());
                                } else if href.starts_with('/') {
                                    let absolute_url = format!("{}{}", target.trim_end_matches('/'), href);
                                    if !visited.contains(&absolute_url) {
                                        visited.insert(absolute_url.clone());
                                        queue.push_back(absolute_url);
                                    }
                                }
                            }
                        }
                    }

                    // --- 4. Looking for Forms (Future XSS/CSRF testing) ---
                    if let Ok(form_selector) = Selector::parse("form") {
                        if document.select(&form_selector).count() > 0 {
                            all_findings.push(Finding {
                                url: url.clone(),
                                vulnerability: "FormFound".to_string(),
                                severity: "LOW".to_string(),
                                evidence: format!("Found {} form(s) on this page. Potential for XSS/SQLi.", document.select(&form_selector).count()),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                println!("Request to {} failed: {}", url, e);
                all_findings.push(Finding {
                    url: url.clone(),
                    vulnerability: "ConnectionError".to_string(),
                    severity: "HIGH".to_string(),
                    evidence: format!("Scanner could not reach the target: {}", e),
                });
            }
        }
    }

    let is_offline = all_findings.iter().any(|f| f.vulnerability == "ConnectionError");

    if !is_offline {
        // Module: Directory Enumeration
        println!("Starting Directory Enumeration on base target...");
        let sensitive_paths = ["/.git/", "/admin", "/backup", "/config.php", "/dashboard", "/.env"];
        let base_url = target.trim_end_matches('/');
        
        for path in sensitive_paths {
            let enum_url = format!("{}{}", base_url, path);
            println!("Checking directory: {}", enum_url);
            
            if let Ok(response) = client.get(&enum_url).send().await {
                let status = response.status();
                if status.is_success() || status == 401 || status == 403 {
                    all_findings.push(Finding {
                        url: enum_url.clone(),
                        vulnerability: "DirectoryEnumeration".to_string(),
                        severity: "MEDIUM".to_string(),
                        evidence: format!("Discovered sensitive path (HTTP {}): {}", status, path),
                    });
                }
            }
        }
    }

    // Update DB
    let mut lock = db.lock().unwrap();
    if let Some(job) = lock.get_mut(&scan_id) {
        job.status = ScanStatus::Done;
        job.findings = all_findings;
    }
}

async fn check_reflected_xss(client: &Client, url_str: &str, findings: &mut Vec<Finding>) {
    let mut url = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return,
    };

    let params: Vec<(String, String)> = url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    if params.is_empty() {
        return;
    }

    // Common XSS payload
    let payload = "<script>alert('xss')</script>";

    for (i, (key, _)) in params.iter().enumerate() {
        let mut test_params = params.clone();
        test_params[i].1 = payload.to_string();

        // Reconstruct URL with injected payload
        url.set_query(None);
        {
            let mut query = url.query_pairs_mut();
            for (k, v) in test_params {
                query.append_pair(&k, &v);
            }
        }

        let test_url = url.to_string();
        if let Ok(resp) = client.get(&test_url).send().await {
            // Check if Content-Type is HTML-ish
            let is_html = resp.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("text/html"))
                .unwrap_or(false);

            if is_html {
                if let Ok(text) = resp.text().await {
                    if text.contains(payload) {
                        findings.push(Finding {
                            url: url_str.to_string(),
                            vulnerability: "ReflectedXSS".to_string(),
                            severity: "HIGH".to_string(),
                            evidence: format!("Query parameter '{}' is reflected in the response without sanitization. Payload: {}", key, payload),
                        });
                    }
                }
            }
        }
    }
}
