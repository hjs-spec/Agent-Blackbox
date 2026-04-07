"""
Command-line interface for Agent Blame-Finder.
"""

import argparse
import json
import sys
import os
from .core import BlameFinder, Verdict


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="blame-finder",
        description="Cryptographic blackbox for multi-agent systems. Find out which agent messed up in 3 seconds."
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # blame command
    blame_parser = subparsers.add_parser("blame", help="Analyze an incident")
    blame_parser.add_argument("incident_id", help="Hash of the incident receipt")
    blame_parser.add_argument("--storage", default="./blackbox_logs", help="Path to storage directory")

    # dashboard command
    dashboard_parser = subparsers.add_parser("dashboard", help="Launch visual dashboard")
    dashboard_parser.add_argument("--storage", default="./blackbox_logs", help="Path to storage directory")
    dashboard_parser.add_argument("--port", type=int, default=8080, help="Port for the dashboard server")

    # tree command
    tree_parser = subparsers.add_parser("tree", help="Show causality tree")
    tree_parser.add_argument("root_hash", help="Hash of the root receipt")
    tree_parser.add_argument("--storage", default="./blackbox_logs", help="Path to storage directory")

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a receipt chain")
    verify_parser.add_argument("receipt_hash", help="Hash of the receipt to verify")
    verify_parser.add_argument("--storage", default="./blackbox_logs", help="Path to storage directory")

    args = parser.parse_args()

    if args.command == "blame":
        _run_blame(args)
    elif args.command == "dashboard":
        _run_dashboard(args)
    elif args.command == "tree":
        _run_tree(args)
    elif args.command == "verify":
        _run_verify(args)
    else:
        parser.print_help()
        sys.exit(1)


def _run_blame(args):
    """Execute blame command."""
    finder = BlameFinder(storage=args.storage)
    result = finder.blame(args.incident_id)

    print("\n" + "=" * 60)
    print("🔍 BLAME ANALYSIS RESULT")
    print("=" * 60)

    if result["verdict"] == "not_found":
        print(f"\n❌ Incident '{args.incident_id}' not found.")
        return

    print(f"\n📋 Incident: {args.incident_id[:16]}...")
    print(f"🎯 Verdict: {result['verdict']}")
    print(f"💡 Reason: {result['reason']}")
    print(f"📊 Confidence: {result.get('confidence', 0) * 100:.0f}%")

    if "chain" in result and result["chain"]:
        print("\n🔗 Responsibility Chain:")
        print("-" * 40)
        for i, node in enumerate(result["chain"]):
            status_icon = "✅" if node["status"] == "success" else "❌" if node["status"] == "failed" else "⏳"
            print(f"  {i+1}. {status_icon} {node['agent']} ({node['verb']}) - {node['status']}")

    print("\n" + "=" * 60)


def _run_dashboard(args):
    """Launch the visual dashboard."""
    print(f"🚀 Starting Blame-Finder Dashboard on port {args.port}...")
    print(f"📁 Storage: {args.storage}")
    print(f"🌐 Open http://localhost:{args.port} in your browser")
    print("\nPress Ctrl+C to stop.")

    try:
        from http.server import HTTPServer, SimpleHTTPRequestHandler
        import threading
        import webbrowser

        # Create a simple dashboard HTML
        dashboard_html = _generate_dashboard_html(args.storage)

        # Write to temp file
        import tempfile
        temp_dir = tempfile.mkdtemp()
        html_path = os.path.join(temp_dir, "dashboard.html")
        with open(html_path, "w") as f:
            f.write(dashboard_html)

        # Change to temp dir and start server
        os.chdir(temp_dir)
        webbrowser.open(f"http://localhost:{args.port}/dashboard.html")

        handler = SimpleHTTPRequestHandler
        httpd = HTTPServer(("localhost", args.port), handler)
        httpd.serve_forever()

    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped.")
    except ImportError:
        print("⚠️ Dashboard requires Python standard library (no extra dependencies).")


def _run_tree(args):
    """Execute tree command."""
    finder = BlameFinder(storage=args.storage)
    tree = finder.get_causality_tree(args.root_hash)

    print("\n" + "=" * 60)
    print("🌲 CAUSALITY TREE")
    print("=" + "=" * 60)
    _print_tree(tree, indent=0)
    print("=" * 60)


def _print_tree(node, indent=0):
    """Pretty print a causality tree."""
    prefix = "  " * indent
    if node.get("missing"):
        print(f"{prefix}❌ [MISSING] {node['hash'][:16]}...")
        return

    agent = node.get("agent", "unknown")
    verb = node.get("verb", "?")
    hash_short = node.get("hash", "")[:16] + "..."

    status_icon = "✅" if node.get("status") == "success" else "❌" if node.get("status") == "failed" else "📝"
    print(f"{prefix}{status_icon} {agent} ({verb}) - {hash_short}")

    for child in node.get("children", []):
        _print_tree(child, indent + 1)


def _run_verify(args):
    """Execute verify command."""
    finder = BlameFinder(storage=args.storage)
    receipt = finder._load_receipt(args.receipt_hash)

    if not receipt:
        print(f"❌ Receipt '{args.receipt_hash}' not found.")
        return

    print("\n" + "=" * 60)
    print("🔐 RECEIPT VERIFICATION")
    print("=" * 60)

    print(f"\n📄 Receipt: {args.receipt_hash[:16]}...")
    print(f"👤 Agent: {receipt.who}")
    print(f"🔖 Verb: {receipt.verb.value}")
    print(f"⏰ Timestamp: {receipt.when}")

    if receipt.task_based_on:
        print(f"🔗 Parent Task: {receipt.task_based_on[:16]}...")

    # Verify signature
    agent_key = finder._get_agent_public_key(receipt.who)
    is_valid = receipt.verify(agent_key)

    print("\n" + "-" * 40)
    if is_valid:
        print("✅ Signature: VALID")
    else:
        print("❌ Signature: INVALID")

    print("=" * 60)


def _generate_dashboard_html(storage_path: str) -> str:
    """Generate the HTML for the visual dashboard."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agent Blame-Finder Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #eee;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .subtitle {
            color: #888;
            margin-bottom: 30px;
            border-left: 3px solid #e74c3c;
            padding-left: 15px;
        }
        .card {
            background: rgba(255,255,255,0.08);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: #e74c3c;
        }
        .stat-label {
            font-size: 0.85rem;
            color: #aaa;
            margin-top: 5px;
        }
        .search-box {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        .search-box input {
            flex: 1;
            padding: 12px;
            border-radius: 8px;
            border: none;
            background: rgba(255,255,255,0.1);
            color: white;
            font-size: 1rem;
        }
        .search-box button {
            padding: 12px 24px;
            border-radius: 8px;
            border: none;
            background: #e74c3c;
            color: white;
            font-weight: bold;
            cursor: pointer;
        }
        .result {
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            padding: 15px;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
        }
        .blame-highlight {
            color: #e74c3c;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #555;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>
            <span>🔍</span>
            Agent Blame-Finder
        </h1>
        <div class="subtitle">
            "Find out which Agent messed up in 3 seconds."
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="agentCount">-</div>
                <div class="stat-label">Active Agents</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="receiptCount">-</div>
                <div class="stat-label">JEP Receipts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="incidentCount">-</div>
                <div class="stat-label">Incidents Analyzed</div>
            </div>
        </div>

        <div class="card">
            <h3>🎯 Blame Analysis</h3>
            <div class="search-box">
                <input type="text" id="incidentId" placeholder="Enter incident ID (receipt hash)..." />
                <button onclick="analyzeBlame()">🔍 Find Blame</button>
            </div>
            <div id="blameResult" class="result">
                <span style="color: #666;">Enter an incident ID to see who's responsible...</span>
            </div>
        </div>

        <div class="footer">
            Powered by JEP (Judgment Event Protocol) & JAC (Judgment Accountability Chain)
        </div>
    </div>

    <script>
        // Mock data - in production, this would call the backend API
        function analyzeBlame() {
            const incidentId = document.getElementById('incidentId').value;
            const resultDiv = document.getElementById('blameResult');

            if (!incidentId) {
                resultDiv.innerHTML = '<span style="color: #e74c3c;">❌ Please enter an incident ID</span>';
                return;
            }

            // Simulate API call
            resultDiv.innerHTML = '<span style="color: #f39c12;">⏳ Analyzing blame chain...</span>';

            setTimeout(() => {
                // This is mock data. Replace with actual API call to /api/blame/{incidentId}
                resultDiv.innerHTML = `
                    <div><span class="blame-highlight">🎯 Verdict:</span> Coder-Agent</div>
                    <div style="margin-top: 10px;"><span class="blame-highlight">💡 Reason:</span> Input requirement was correct, but output didn't match expectations</div>
                    <div style="margin-top: 10px;"><span class="blame-highlight">📊 Confidence:</span> 94%</div>
                    <div style="margin-top: 15px;"><span class="blame-highlight">🔗 Chain:</span></div>
                    <div style="margin-left: 20px;">
                        <div>✅ 1. PM-Agent (J) - success</div>
                        <div>❌ 2. Coder-Agent (J) - failed</div>
                        <div>⏳ 3. Verifier-Agent (V) - not_reached</div>
                    </div>
                    <div style="margin-top: 10px; color: #e74c3c;">👤 Blame assigned to: <strong>Coder-Agent</strong></div>
                `;
            }, 1000);
        }

        // Update stats
        document.getElementById('agentCount').innerText = '3';
        document.getElementById('receiptCount').innerText = '47';
        document.getElementById('incidentCount').innerText = '12';
    </script>
</body>
</html>
    """


if __name__ == "__main__":
    main()
