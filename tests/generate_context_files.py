#!/usr/bin/env python3
"""
Generate consolidated context files for AI agents:
- ProductDocumentation.txt: concatenated key docs and READMEs
- SolutionFileStructure.txt: recursive file list
- DomainModels.txt: concatenated domain model files
- Services.txt: concatenated service-like modules (routes, workers, utils)
- Presentation.txt: selected front-end HTML + v2 JS

Usage:
  python tests/generate_context_files.py
"""
import os
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]

OUTS = {
    "ProductDocumentation.txt": BASE / "ProductDocumentation.txt",
    "SolutionFileStructure.txt": BASE / "SolutionFileStructure.txt",
    "DomainModels.txt": BASE / "DomainModels.txt",
    "Services.txt": BASE / "Services.txt",
    "Presentation.txt": BASE / "Presentation.txt",
}


def safe_read(fp: Path) -> str:
    try:
        return fp.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def write_out(name: str, content: str):
    OUTS[name].write_text(content, encoding="utf-8")
    print(f"Wrote {name} ({len(content)} bytes)")


def build_product_docs() -> str:
    sections = []
    candidates = [
        BASE / "README.md",
        BASE / "PROJECT_SUMMARY.md",
        BASE / "OVERVIEW.md",
        BASE / "docs" / "START_HERE.md",
        BASE / "docs" / "README.md",
        BASE / "docs" / "ARCHITECTURE_DECISIONS.md",
        BASE / "docs" / "TECHNIEUM_DOCUMENTATION.md",
        BASE / "docs" / "DOCUMENTATION.md",
        BASE / "docs" / "QUICKSTART.md",
        BASE / "docs" / "FAQ.md",
        BASE / "docs" / "MIGRATION_PLAN.md",
        BASE / "docs" / "ENTERPRISE_ROADMAP.md",
        BASE / "docs" / "SECURITY_AUDIT_RESPONSE.md",
    ]
    for fp in candidates:
        if fp.exists():
            sections.append(f"\n\n===== {fp.relative_to(BASE)} =====\n\n")
            sections.append(safe_read(fp))
    return "".join(sections) or "(No documentation files found)"


def build_solution_structure() -> str:
    lines = []
    for fp in BASE.rglob("*"):
        # Skip some heavy or irrelevant dirs
        if any(part in fp.parts for part in ["venv", "__pycache__", ".git", "node_modules", "output", "logs"]):
            continue
        lines.append(str(fp.relative_to(BASE)))
    return "\n".join(sorted(lines))


def build_domain_models() -> str:
    lines = []
    candidates = []
    # common model locations
    candidates += list((BASE / "app" / "api" / "models").rglob("*.py"))
    candidates += [BASE / "app" / "db" / "models.py"]
    candidates += list((BASE / "backend" / "db").rglob("*.py"))
    # Concatenate with separators
    for fp in candidates:
        if fp.exists():
            lines.append(f"\n\n# >>> {fp.relative_to(BASE)}\n\n")
            lines.append(safe_read(fp))
    return "".join(lines) or "(No domain model files found)"


def build_services() -> str:
    lines = []
    candidates = []
    # Routes (service layer), workers, utils
    candidates += list((BASE / "app" / "api" / "routes").rglob("*.py"))
    candidates += list((BASE / "app" / "workers").rglob("*.py"))
    candidates += list((BASE / "backend" / "api").rglob("*.py"))
    candidates += list((BASE / "backend" / "utils").rglob("*.py"))
    for fp in candidates:
        if fp.exists():
            lines.append(f"\n\n# >>> {fp.relative_to(BASE)}\n\n")
            lines.append(safe_read(fp))
    return "".join(lines) or "(No service files found)"


def build_presentation() -> str:
    lines = []
    # Key HTML pages
    htmls = [
        BASE / "web" / "static" / "index.html",
        BASE / "web" / "static" / "scan_viewer_v2.html",
        BASE / "web" / "static" / "findings_v2.html",
        BASE / "web" / "static" / "graph_viewer_v2.html",
        BASE / "web" / "static" / "attack_surface_v2.html",
        BASE / "web" / "static" / "reports_v2.html",
        BASE / "web" / "static" / "compliance_v2.html",
        BASE / "web" / "static" / "alerts_v2.html",
        BASE / "web" / "static" / "settings_v2.html",
        BASE / "web" / "static" / "threat_intel_v2.html",
    ]
    for fp in htmls:
        if fp.exists():
            lines.append(f"\n\n<!-- >>> {fp.relative_to(BASE)} -->\n\n")
            lines.append(safe_read(fp))
    # v2 JS files
    jsdir = BASE / "web" / "static" / "assets" / "js"
    for name in [
        "dashboard-v2.js",
        "scan_monitor_v2.js",
        "findings_v2.js",
        "graph_viz_v2.js",
    ]:
        fp = jsdir / name
        if fp.exists():
            lines.append(f"\n\n// >>> {fp.relative_to(BASE)}\n\n")
            lines.append(safe_read(fp))
    return "".join(lines) or "(No front-end files found)"


def main():
    proddocs = build_product_docs()
    write_out("ProductDocumentation.txt", proddocs)

    structure = build_solution_structure()
    write_out("SolutionFileStructure.txt", structure)

    domains = build_domain_models()
    write_out("DomainModels.txt", domains)

    services = build_services()
    write_out("Services.txt", services)

    presentation = build_presentation()
    write_out("Presentation.txt", presentation)


if __name__ == "__main__":
    main()
