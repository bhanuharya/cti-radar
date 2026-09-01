//! Report generation: HTML fallback + optional Chromium PDF render.

use serde_json::{json, Map, Value};

/// Build the printable HTML report (PII-masked findings).
pub fn build_report_html(
    slug: &str,
    org: &Value,
    findings: &[Value],
    domains: &[String],
) -> String {
    let name = org.get("name").and_then(|v| v.as_str()).unwrap_or(slug);
    let domains_s = domains.join(", ");
    let date_s = crate::correlation::now_iso()[..10].to_string();

    let mut sev_counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for f in findings {
        let s = f.get("severity").and_then(|v| v.as_str()).unwrap_or("INFO");
        *sev_counts.entry(s).or_insert(0) += 1;
    }

    let sev_rows: String = sev_counts
        .iter()
        .map(|(k, v)| format!("<tr><td>{}</td><td>{}</td></tr>", esc(k), v))
        .collect();

    let sections: String = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let title = f
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("(untitled)");
            let mut rows = String::new();
            for key in [
                "id",
                "title",
                "severity",
                "cvss_estimate",
                "cvss_vector",
                "target",
                "ip",
                "category",
                "status",
                "description",
                "impact",
                "evidence",
                "proof_chain",
                "remediation",
                "related_cves",
                "topics_exposed",
                "discovery",
            ] {
                if let Some(v) = f.get(key) {
                    rows.push_str(&format!(
                        "<tr><th>{}</th><td>{}</td></tr>",
                        esc(key),
                        render_value(v)
                    ));
                }
            }
            format!(
                "<section class='finding'><h2>{}. {}</h2><table>{}</table></section>",
                i + 1,
                esc(title),
                rows
            )
        })
        .collect();

    format!(
        r#"<!doctype html>
<html><head><meta charset='utf-8'>
<title>CTI Report — {name}</title>
<style>
 body {{ font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
         color: #1a1a2e; margin: 0; }}
 .cover {{ padding: 80px 60px; page-break-after: always; }}
 .cover h1 {{ font-size: 34px; margin-bottom: 8px; }}
 .cover .sub {{ color: #555; font-size: 16px; margin-bottom: 40px; }}
 table {{ width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 13px; }}
 th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left;
            vertical-align: top; word-break: break-word; }}
 th {{ background: #f4f4f8; width: 180px; }}
 h2 {{ font-size: 16px; margin: 26px 0 4px; border-bottom: 2px solid #eee;
       padding-bottom: 4px; }}
 .finding {{ padding: 0 24px; page-break-inside: avoid; }}
 pre {{ white-space: pre-wrap; font-size: 12px; margin: 0; }}
 .na {{ color: #999; }}
</style></head>
<body>
<div class='cover'>
  <h1>CTI Radar — Correlation Report</h1>
  <div class='sub'>{name} &middot; {date_s}</div>
  <p><strong>Domains:</strong> {domains_s}</p>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    {sev_rows}
    <tr><th>Total findings</th><th>{total}</th></tr>
  </table>
</div>
{sections}
</body></html>"#,
        name = name,
        date_s = date_s,
        domains_s = domains_s,
        sev_rows = sev_rows,
        total = findings.len(),
        sections = sections,
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_value(v: &Value) -> String {
    match v {
        Value::Null => "<span class='na'>&mdash;</span>".to_string(),
        Value::Bool(b) => esc(&b.to_string()),
        Value::Array(arr) if arr.is_empty() => "<span class='na'>&mdash;</span>".to_string(),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(render_value).collect();
            format!(
                "<ul>{}</ul>",
                items
                    .iter()
                    .map(|i| format!("<li>{}</li>", i))
                    .collect::<String>()
            )
        }
        Value::Object(o) if o.is_empty() => "<span class='na'>&mdash;</span>".to_string(),
        Value::Object(o) => {
            let pretty = serde_json::to_string_pretty(o).unwrap_or_default();
            format!("<pre>{}</pre>", esc(&pretty))
        }
        Value::String(s) => esc(s),
        Value::Number(n) => esc(&n.to_string()),
    }
}

/// Render PDF via headless Chromium; returns None to fall back to HTML.
pub async fn render_pdf(_slug: &str, html: &str, chromium: &str) -> Option<Vec<u8>> {
    // Write HTML to a temp file, invoke chromium headless --print-to-pdf.
    let dir = std::env::temp_dir();
    let html_path = dir.join(format!("cti-report-{}.html", uuid::Uuid::new_v4().simple()));
    let pdf_path = dir.join(format!("cti-report-{}.pdf", uuid::Uuid::new_v4().simple()));
    std::fs::write(&html_path, html).ok()?;

    let result = tokio::process::Command::new(chromium)
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            &format!("--print-to-pdf={}", pdf_path.display()),
            "--no-pdf-header-footer",
            &format!("file://{}", html_path.display()),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .ok();

    let pdf = match result {
        Some(out) if out.status.success() => std::fs::read(&pdf_path).ok(),
        _ => None,
    };

    let _ = std::fs::remove_file(&html_path);
    let _ = std::fs::remove_file(&pdf_path);

    match pdf {
        Some(bytes) if !bytes.is_empty() && bytes.len() <= 20 * 1024 * 1024 => Some(bytes),
        _ => None,
    }
}

#[allow(dead_code)]
fn _unused() -> Map<String, Value> {
    Map::new()
}

#[allow(dead_code)]
fn _unused_json() -> Value {
    json!({})
}
