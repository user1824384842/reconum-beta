import json
import os
from datetime import datetime

# Formatting constants for the "Professional" look
SEVERITY_COLORS = {
    "critical": "danger", # Red
    "high": "warning",   # Orange
    "medium": "primary",   # Yellow/Blue
    "low": "info",      # Light Blue
    "info": "secondary"    # Grey
}

def generate_html(targets):
    # --- Statistics Calculation ---
    total_targets = len(targets)
    live_targets = sum(1 for t in targets if not t.get('is_dead', False))
    total_vulns = sum(len(t.get('vulnerabilities', [])) for t in targets)
    criticals = sum(1 for t in targets for v in t.get('vulnerabilities', []) if v['severity'].lower() == 'critical')

    # --- HTML Template ---
    # Using Bootstrap 5 for the UI and DataTables for the interactive table
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>flu1d RECONUM Report - {datetime.now().strftime('%Y-%m-%d')}</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css">
        <style>
            body {{ background-color: #f8f9fa; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
            .stats-card {{ border-left: 5px solid #0d6efd; transition: transform 0.2s; }}
            .stats-card:hover {{ transform: translateY(-5px); }}
            .severity-critical {{ background-color: #dc3545 !important; color: white; }}
            .severity-high {{ background-color: #fd7e14 !important; color: white; }}
            .vuln-badge {{ border-radius: 12px; padding: 2px 10px; font-weight: bold; font-size: 0.8em; }}
            pre {{ background: #212529; color: #00ff00; padding: 10px; border-radius: 5px; font-size: 0.9em; }}
            .target-row {{ cursor: pointer; }}
        </style>
    </head>
    <body>
        <div class="container my-5">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h1 class="display-4 fw-bold text-dark">flu1d <span class="text-primary">RECONUM</span></h1>
                <span class="badge bg-dark fs-6">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
            </div>

            <!-- Dashboard Summary -->
            <div class="row mb-5">
                <div class="col-md-3">
                    <div class="card stats-card shadow-sm p-3">
                        <small class="text-muted fw-bold">TOTAL TARGETS</small>
                        <h2 class="fw-bold">{total_targets}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card stats-card shadow-sm p-3" style="border-left-color: #198754;">
                        <small class="text-muted fw-bold">LIVE HOSTS</small>
                        <h2 class="fw-bold text-success">{live_targets}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card stats-card shadow-sm p-3" style="border-left-color: #ffc107;">
                        <small class="text-muted fw-bold">VULNERABILITIES</small>
                        <h2 class="fw-bold text-warning">{total_vulns}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card stats-card shadow-sm p-3" style="border-left-color: #dc3545;">
                        <small class="text-muted fw-bold">CRITICAL BUGS</small>
                        <h2 class="fw-bold text-danger">{criticals}</h2>
                    </div>
                </div>
            </div>

            <!-- Main Findings Table -->
            <div class="card shadow-sm mb-5">
                <div class="card-header bg-white py-3">
                    <h5 class="mb-0 fw-bold">Network Findings</h5>
                </div>
                <div class="card-body">
                    <table id="findingsTable" class="table table-hover align-middle">
                        <thead class="table-light">
                            <tr>
                                <th>Address</th>
                                <th>Status</th>
                                <th>Open Ports</th>
                                <th>Services Identified</th>
                                <th>Top Severity</th>
                            </tr>
                        </thead>
                        <tbody>
    """

    for t in targets:
        # Calculate max severity for this target
        vulns = t.get('vulnerabilities', [])
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_sev = "info"
        if vulns:
            max_sev = max(vulns, key=lambda x: sev_rank.get(x['severity'].lower(), 0))['severity'].lower()
        
        status_badge = '<span class="badge bg-success">Live</span>' if not t.get('is_dead') else '<span class="badge bg-danger">Dead</span>'
        ports = ", ".join([str(s['port']) for s in t.get('services', [])])
        services = ", ".join([s['name'] for s in t.get('services', [])])
        
        html_template += f"""
                            <tr class="target-row" data-bs-toggle="modal" data-bs-target="#modal-{t['scan_id']}">
                                <td class="fw-bold text-primary">{t['address']}</td>
                                <td>{status_badge}</td>
                                <td>{ports if ports else '---'}</td>
                                <td><small class="text-muted">{services if services else 'None'}</small></td>
                                <td><span class="badge rounded-pill severity-{max_sev}">{max_sev.upper() if vulns else 'NONE'}</span></td>
                            </tr>
        """

    html_template += """
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Modals for Details -->
    """
    
    for t in targets:
        services_html = "".join([f"<li><strong>Port {s['port']}</strong>: {s['product']} {s['version']} ({s['name']})</li>" for s in t.get('services', [])])
        tech_html = "".join([f'<span class="badge bg-light text-dark border me-1">{tech}</span>' for tech in t.get('technologies', [])])
        
        vuln_list_html = ""
        for v in t.get('vulnerabilities', []):
            color = SEVERITY_COLORS.get(v['severity'].lower(), "secondary")
            vuln_list_html += f"""
                <div class="alert alert-{color} border-0 shadow-sm mb-3">
                    <h6 class="fw-bold mb-1">{v['name']} <span class="badge bg-{color} ms-2">{v['severity'].upper()}</span></h6>
                    <p class="mb-2 small">{v['description']}</p>
                    {f'<pre>{chr(10).join(v.get("extracted_results", []))}</pre>' if v.get('extracted_results') else ''}
                </div>
            """

        html_template += f"""
        <div class="modal fade" id="modal-{t['scan_id']}" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header bg-dark text-white">
                        <h5 class="modal-title">Target Intelligence: {t['address']}</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row mb-4">
                            <div class="col-md-6">
                                <h6 class="fw-bold text-muted">Service Inventory</h6>
                                <ul class="list-unstyled small">
                                    {services_html if services_html else '<li>No services found.</li>'}
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <h6 class="fw-bold text-muted">Technology Stack</h6>
                                <div>{tech_html if tech_html else 'None detected.'}</div>
                            </div>
                        </div>
                        <hr>
                        <h6 class="fw-bold text-muted mb-3">Vulnerabilities & Findings</h6>
                        {vuln_list_html if vuln_list_html else '<p class="text-muted">No vulnerabilities detected.</p>'}
                    </div>
                </div>
            </div>
        </div>
        """

    html_template += """
        </div>

        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
        <script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
        <script>
            $(document).ready(function() {
                $('#findingsTable').DataTable({
                    "order": [[4, "desc"]], // Sort by severity initially
                    "pageLength": 25
                });
            });
        </script>
    </body>
    </html>
    """
    return html_template

def run_reporter():
    input_file = "scans/session_results.jsonl"
    output_file = "scans/report.html"

    if not os.path.exists(input_file):
        print(f"[!] Error: {input_file} not found. Run a scan first!")
        return

    targets = []
    with open(input_file, "r") as f:
        for line in f:
            try:
                targets.append(json.loads(line))
            except: continue

    print(f"[*] Parsing {len(targets)} targets for report...")
    report_content = generate_html(targets)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report_content)
    
    print(f"[+] Report generated successfully: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    run_reporter()