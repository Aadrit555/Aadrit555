#!/usr/bin/env python3
"""
Profile validation suite for Aadrit555/Aadrit555.
Runs deterministic repository integrity, security, and syntax checks.
Zero external dependencies (Python standard library only).
"""

import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_FILES = [
    "README.md",
    "assets/header.svg",
    "assets/footer.svg",
    ".github/workflows/validate-profile.yml",
    ".github/dependabot.yml",
]

CREDENTIAL_PATTERNS = [
    (re.compile(r"ghp_[A-Za-z0-9_]{36,}"), "GitHub Personal Access Token (classic)"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{60,}"), "GitHub Fine-Grained Personal Access Token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Private Key header"),
    (re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"), "AWS Access Key ID"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z]{10,48}"), "Slack API Token"),
]

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
ACTION_USES_PATTERN = re.compile(r"^\s*uses:\s*['\"]?([^'\"\s#]+)")


def check_required_files() -> list[str]:
    errors = []
    for rel_path in REQUIRED_FILES:
        target = REPO_ROOT / rel_path
        if not target.is_file():
            errors.append(f"Missing required file: {rel_path}")
        elif target.stat().st_size == 0:
            errors.append(f"Required file is empty: {rel_path}")
    return errors


def check_svg_validity() -> list[str]:
    errors = []
    assets_dir = REPO_ROOT / "assets"
    if not assets_dir.is_dir():
        return ["assets/ directory does not exist"]

    svg_files = list(assets_dir.glob("*.svg"))
    if not svg_files:
        errors.append("No SVG files found in assets/")

    for svg_path in svg_files:
        try:
            tree = ET.parse(svg_path)
            root = tree.getroot()
            if not root.tag.endswith("svg"):
                errors.append(f"{svg_path.name} root element is not <svg> (found {root.tag})")
        except ET.ParseError as e:
            errors.append(f"Malformed XML in {svg_path.relative_to(REPO_ROOT)}: {e}")
        except Exception as e:
            errors.append(f"Error reading {svg_path.relative_to(REPO_ROOT)}: {e}")
    return errors


def check_readme_local_links() -> list[str]:
    errors = []
    readme_path = REPO_ROOT / "README.md"
    if not readme_path.is_file():
        return ["README.md not found"]

    content = readme_path.read_text(encoding="utf-8")

    # Match markdown [text](path) and ![alt](path)
    md_links = re.findall(r'!?\[.*?\]\(([^)]+)\)', content)
    # Match html src="..." and href="..."
    html_links = re.findall(r'(?:src|href)=["\']([^"\']+)["\']', content)

    all_links = set(md_links + html_links)
    for link in all_links:
        link_clean = link.strip()
        # Skip external, anchor, and mailto links
        if link_clean.startswith(("http://", "https://", "mailto:", "#", "tel:")):
            continue

        # Strip optional query parameters/fragments from local path
        local_path_str = link_clean.split("?")[0].split("#")[0]
        if not local_path_str:
            continue

        local_path = (REPO_ROOT / local_path_str).resolve()
        # Ensure path stays within repo root
        try:
            local_path.relative_to(REPO_ROOT)
        except ValueError:
            errors.append(f"Local link attempts path traversal: {link}")
            continue

        if not local_path.exists():
            errors.append(f"Broken local link in README.md: '{link}' -> {local_path_str} does not exist")

    return errors


def check_readme_structure() -> list[str]:
    errors = []
    readme_path = REPO_ROOT / "README.md"
    if not readme_path.is_file():
        return ["README.md not found"]

    content = readme_path.read_text(encoding="utf-8")

    expected_sections = [
        (re.compile(r"Hey,?\s+I'm\s+.*Aadrit", re.IGNORECASE), "Identity / Introduction"),
        (re.compile(r"Current Focus|What I'm Working On", re.IGNORECASE), "Current Focus"),
        (re.compile(r"Projects|Featured Projects", re.IGNORECASE), "Projects"),
        (re.compile(r"Technologies|Technical Stack|Skills", re.IGNORECASE), "Technologies"),
        (re.compile(r"GitHub Overview|Activity & Metrics|Activity|Contribution", re.IGNORECASE), "GitHub Overview / Activity section"),
    ]

    for pattern, name in expected_sections:
        if not pattern.search(content):
            errors.append(f"README.md is missing expected section: '{name}'")

    return errors


def check_github_links() -> list[str]:
    errors = []
    readme_path = REPO_ROOT / "README.md"
    if not readme_path.is_file():
        return []

    content = readme_path.read_text(encoding="utf-8")
    github_urls = re.findall(r'https://github\.com/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?', content)

    if not github_urls:
        errors.append("No GitHub links found in README.md")

    for url in set(github_urls):
        # Verify basic syntax: https://github.com/owner or https://github.com/owner/repo
        parts = url.replace("https://github.com/", "").split("/")
        if not parts[0]:
            errors.append(f"Invalid GitHub URL syntax: {url}")
        elif len(parts) > 2:
            errors.append(f"Unexpected GitHub URL format: {url}")

    return errors


def check_workflow_pinning() -> list[str]:
    errors = []
    workflows_dir = REPO_ROOT / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return ["No .github/workflows directory found"]

    workflow_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
    if not workflow_files:
        return ["No workflow files found in .github/workflows/"]

    for wf in workflow_files:
        for line_num, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), start=1):
            match = ACTION_USES_PATTERN.match(line)
            if match:
                action_ref = match.group(1).strip()
                # Skip local actions (starting with ./) or docker actions
                if action_ref.startswith(("./", "docker://")):
                    continue

                if "@" not in action_ref:
                    errors.append(
                        f"{wf.name}:{line_num}: Action '{action_ref}' is missing a commit SHA reference"
                    )
                    continue

                action_name, ref = action_ref.split("@", 1)
                if not SHA_PATTERN.match(ref):
                    errors.append(
                        f"{wf.name}:{line_num}: Third-party Action '{action_name}' must be pinned to a full 40-character commit SHA (found: '{ref}')"
                    )

    return errors


def check_credential_leakage() -> list[str]:
    errors = []
    # Files to check: all regular files under repo root excluding .git
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        # Skip .git directory and python cache
        rel_str = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
        if rel_str.startswith((".git/", "__pycache__/", ".pytest_cache/")):
            continue
        if path.suffix in [".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2"]:
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, label in CREDENTIAL_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                errors.append(
                    f"{rel_str}: Potential {label} detected: {matches[0][:8]}... (truncated)"
                )

    return errors


def run_all_checks() -> bool:
    checks = [
        ("Required files check", check_required_files),
        ("SVG XML validity check", check_svg_validity),
        ("README local links check", check_readme_local_links),
        ("README structure check", check_readme_structure),
        ("GitHub links format check", check_github_links),
        ("GitHub Actions SHA pinning check", check_workflow_pinning),
        ("Credential scan", check_credential_leakage),
    ]

    all_passed = True
    print("=" * 60)
    print("Profile Integrity & Security Validation Suite")
    print("=" * 60)

    for name, check_fn in checks:
        errors = check_fn()
        if errors:
            all_passed = False
            print(f"[-] FAIL: {name}")
            for err in errors:
                print(f"    - {err}")
        else:
            print(f"[+] PASS: {name}")

    print("=" * 60)
    if all_passed:
        print("ALL CHECKS PASSED: Repository is clean, valid, and secured.")
    else:
        print("FAILURES DETECTED: Correct the issues above before committing.")
    print("=" * 60)

    return all_passed


if __name__ == "__main__":
    success = run_all_checks()
    sys.exit(0 if success else 1)

