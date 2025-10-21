#!/usr/bin/env python3
"""
Self-contained script to generate compliance dashboard and all server reports.
Automatically discovers servers with .duvet/reports/report.html files and generates
individual reports using the enhanced report-based format with deep links, source traceability,
copy buttons, and comprehensive statistics.
"""

import json
import re
import os
from pathlib import Path
from datetime import datetime


def parse_report_html(report_file_path):
    """Parse the report.html file and extract specification data."""
    with open(report_file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Extract JSON from script tag with id="result"
    start_marker = '<script type="application/json" id=result>'
    end_marker = "</script>"

    start_idx = content.find(start_marker)
    if start_idx == -1:
        raise ValueError("No result script tag found in HTML")

    start_idx += len(start_marker)
    end_idx = content.find(end_marker, start_idx)
    if end_idx == -1:
        raise ValueError("No closing script tag found")

    json_content = content[start_idx:end_idx]
    data = json.loads(json_content)

    # Convert report.html JSON structure to match snapshot structure
    return convert_report_to_specifications(data)


def convert_report_to_specifications(data):
    """Convert duvet report.html JSON structure to match snapshot structure."""
    specifications = {}

    for spec_path, spec in (data.get("specifications", {})).items():
        spec_data = {
            "title": spec.get("title", "Unknown"),
            "spec_path": spec_path,  # Store the original spec path
            "sections": {},
        }

        # Process sections - sections is a list, not a dict
        for section in spec.get("sections", []):
            section_data = {
                "title": section.get("title", "Unknown"),
                "section_id": section.get("id", "unknown"),  # Store the section ID
                "requirements": [],
            }

            # Process requirements for this section
            for req_id in section.get("requirements", []):
                # Get annotation data
                annotation = None
                if "annotations" in data and isinstance(data["annotations"], list):
                    # annotations is a list indexed by req_id
                    if req_id < len(data["annotations"]):
                        annotation = data["annotations"][req_id]

                # Get status data
                status = None
                if "statuses" in data and isinstance(data["statuses"], dict):
                    status = data["statuses"].get(str(req_id))

                if annotation and status:
                    # Parse status indicators (matching snapshot logic)
                    has_implementation = bool(
                        status.get("citation")
                    )  # Only citation counts as implementation
                    has_test = bool(status.get("test"))
                    has_exception = bool(status.get("exception"))
                    has_implication = bool(status.get("implication"))
                    has_partial_coverage = bool(status.get("incomplete"))

                    # Determine completion status (matching snapshot rules exactly)
                    is_complete = (
                        (has_implementation and has_test) or has_exception or has_implication
                    ) and not has_partial_coverage  # Partial coverage means not complete

                    # Collect related annotations for detailed status
                    related_sources = []
                    if "related" in status:
                        for related_id in status["related"]:
                            if related_id < len(data["annotations"]):
                                related_annotation = data["annotations"][related_id]
                                source = related_annotation.get("source", "")
                                line = related_annotation.get("line", "")
                                annotation_type = related_annotation.get("type", "CITATION")
                                if source:
                                    source_info = {
                                        "source": source,
                                        "line": line,
                                        "type": annotation_type,
                                    }
                                    related_sources.append(source_info)

                    requirement = {
                        "text": annotation.get("comment", "No comment available"),
                        "has_implementation": has_implementation,
                        "has_test": has_test,
                        "has_exception": has_exception,
                        "has_implication": has_implication,
                        "has_partial_coverage": has_partial_coverage,
                        "is_complete": is_complete,
                        "related_sources": related_sources,
                    }

                    section_data["requirements"].append(requirement)
                elif req_id < len(data.get("annotations", [])):
                    # Fallback: create requirement with basic info
                    annotation = data["annotations"][req_id]
                    requirement = {
                        "text": annotation.get("comment", f"Requirement {req_id}"),
                        "has_implementation": False,
                        "has_test": False,
                        "has_exception": False,
                        "has_implication": False,
                        "is_complete": False,
                        "related_sources": [],
                    }
                    section_data["requirements"].append(requirement)

            spec_data["sections"][section.get("title", "Unknown")] = section_data

        specifications[spec.get("title", "Unknown")] = spec_data

    return specifications


def get_spec_status(spec_data):
    """Determine the overall status of a specification based on all its sections."""
    sections = spec_data.get("sections", {})

    if not sections:
        return "✅"  # No sections means complete

    # Get status of each section
    section_statuses = []
    for section_data in sections.values():
        requirements = section_data.get("requirements", [])
        if not requirements:
            section_statuses.append("✅")  # Empty section is complete
        else:
            complete_reqs = sum(1 for req in requirements if req["is_complete"])
            total_reqs = len(requirements)

            if complete_reqs == total_reqs:
                section_statuses.append("✅")  # All requirements complete
            elif complete_reqs > 0:
                section_statuses.append("🟡")  # Some requirements complete
            else:
                section_statuses.append("❌")  # No requirements complete

    # Apply the corrected logic based on section statuses:
    if all(status == "✅" for status in section_statuses):
        return "✅"  # Green check if all sections are green
    elif any(status in ["✅", "🟡"] for status in section_statuses):
        return "🟡"  # Yellow if any section is green or yellow
    else:
        return "❌"  # Red X if all sections are red X


def get_requirement_status(requirement):
    """Get the status emoji for a single requirement."""
    if requirement["is_complete"]:
        return "✅"
    elif requirement.get("has_partial_coverage", False):
        return "🟡"  # Partial coverage - incomplete
    elif requirement["has_implementation"] and requirement["related_sources"]:
        return "🟡"  # Has implementation but no test
    else:
        return "❌"  # No implementation


def format_requirement_text(text):
    """Format requirement text to style status metadata lines."""
    lines = text.split("\n")
    formatted_lines = []

    for line in lines:
        # Check if line contains status metadata
        if line.strip().startswith("Status:"):
            formatted_lines.append(f'<span class="status-metadata">{line}</span>')
        else:
            formatted_lines.append(line)

    return "\n".join(formatted_lines)


def calculate_summary_statistics(specifications):
    """Calculate summary statistics for all specifications."""
    total_sections = 0
    complete_sections = 0
    total_requirements = 0
    complete_requirements = 0

    # Count requirements by implementation type
    no_implementation = 0
    implementation_only = 0
    test_only = 0
    implementation_and_test = 0
    exception_count = 0
    implication_count = 0
    partial_coverage_count = 0

    for spec_data in specifications.values():
        sections = spec_data.get("sections", {})
        total_sections += len(sections)

        for section_data in sections.values():
            requirements = section_data.get("requirements", [])
            total_requirements += len(requirements)

            # Count complete requirements
            section_complete_reqs = sum(1 for req in requirements if req["is_complete"])
            complete_requirements += section_complete_reqs

            # A section is complete if all its requirements are complete
            if requirements and section_complete_reqs == len(requirements):
                complete_sections += 1
            elif not requirements:  # Empty section is considered complete
                complete_sections += 1

            # Count requirements by implementation type
            for req in requirements:
                if req["has_exception"]:
                    exception_count += 1
                elif req["has_implication"]:
                    implication_count += 1
                elif req["has_implementation"] and req["has_test"] and not req.get("has_partial_coverage", False):
                    implementation_and_test += 1
                elif req["has_implementation"] and not req.get("has_partial_coverage", False):
                    implementation_only += 1
                elif req["has_test"] and not req.get("has_partial_coverage", False):
                    test_only += 1
                else:
                    # Partial coverage gets counted as no implementation
                    no_implementation += 1

    return {
        "total_sections": total_sections,
        "complete_sections": complete_sections,
        "total_requirements": total_requirements,
        "complete_requirements": complete_requirements,
        "no_implementation": no_implementation,
        "implementation_only": implementation_only,
        "test_only": test_only,
        "implementation_and_test": implementation_and_test,
        "exception_count": exception_count,
        "implication_count": implication_count,
        "partial_coverage_count": partial_coverage_count,
    }


def url_encode_spec_path(spec_path):
    """URL encode the spec path for use in duvet report URLs."""
    import urllib.parse

    return urllib.parse.quote(spec_path, safe="")


def generate_spec_url(duvet_report_path, spec_path):
    """Generate URL to a specific specification in the duvet report."""
    encoded_path = url_encode_spec_path(spec_path)
    return f"{duvet_report_path}#/spec/{encoded_path}"

def generate_section_url(duvet_report_path, spec_path, section_id):
    """Generate URL to a specific section in the duvet report."""
    encoded_path = url_encode_spec_path(spec_path)
    return f"{duvet_report_path}#/spec/{encoded_path}/{section_id}"

def generate_github_url(source_path, line_number=None, github_base_url=None):
    """Generate GitHub URL for a source file."""
    if not github_base_url:
        return None

    # Convert local path to GitHub path
    # Remove local-go-s3ec/ prefix if present
    if source_path.startswith("local-go-s3ec/"):
        github_path = source_path[len("local-go-s3ec/") :]
    else:
        github_path = source_path

    url = f"{github_base_url}/{github_path}"
    if line_number:
        url += f"#L{line_number}"

    return url


def load_template(template_path):
    """Load a template file."""
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()


def generate_enhanced_html_report(report_file_path, output_file_path, server_name):
    """Generate an enhanced interactive HTML report using templates."""
    specifications = parse_report_html(report_file_path)

    # Load the report template
    template_dir = Path(__file__).parent / "templates"
    template = load_template(template_dir / "report_template.html")

    # Create relative path to the duvet report.html
    duvet_report_path = ".duvet/reports/report.html"

    # GitHub base URL - can be configured for when deployed to GitHub Pages
    github_base_url = None

    # Calculate summary statistics
    stats = calculate_summary_statistics(specifications)

    # Calculate percentages for each implementation type
    total_reqs = stats["total_requirements"]
    if total_reqs > 0:
        # Calculate raw percentages
        impl_test_pct = (stats["implementation_and_test"] / total_reqs) * 100
        impl_only_pct = (stats["implementation_only"] / total_reqs) * 100
        test_only_pct = (stats["test_only"] / total_reqs) * 100
        exception_pct = (stats["exception_count"] / total_reqs) * 100
        implication_pct = (stats["implication_count"] / total_reqs) * 100
        no_impl_pct = (stats["no_implementation"] / total_reqs) * 100
        
        # Ensure percentages add up to exactly 100% by using precise calculation
        # and assigning any remainder to the largest segment
        if total_reqs > 0:
            # Calculate exact percentages using integer arithmetic to avoid floating point errors
            percentages_data = [
                (stats["implementation_and_test"], 'impl_test'),
                (stats["implication_count"], 'implication'),
                (stats["exception_count"], 'exception'),
                (stats["implementation_only"], 'impl_only'),
                (stats["no_implementation"], 'no_impl')
            ]
            
            # Calculate percentages with high precision, then distribute remainder
            total_allocated = 0.0
            calculated_percentages = {}
            
            # Calculate all but the last percentage
            for i, (count, name) in enumerate(percentages_data[:-1]):
                pct = round((count / total_reqs) * 100, 1)
                calculated_percentages[name] = pct
                total_allocated += pct
            
            # Last segment gets the remainder to ensure exactly 100%
            last_count, last_name = percentages_data[-1]
            calculated_percentages[last_name] = round(100.0 - total_allocated, 1)
            
            # Assign back to variables
            impl_test_pct = calculated_percentages['impl_test']
            implication_pct = calculated_percentages['implication'] 
            exception_pct = calculated_percentages['exception']
            impl_only_pct = calculated_percentages['impl_only']
            no_impl_pct = calculated_percentages['no_impl']
    else:
        impl_test_pct = impl_only_pct = test_only_pct = exception_pct = implication_pct = (
            no_impl_pct
        ) = 0

    # Generate summary statistics HTML with color-coded progress bars
    content_html = f"""
        <div class="summary-stats">
            <div class="progress-section">
                <div class="progress-item">
                    <div class="progress-header">
                        <span class="progress-label">Requirements by Implementation Type</span>
                        <span class="progress-count">{stats['complete_requirements']}/{stats['total_requirements']} <span title="implementation+test, implication, or exception" style="border-bottom: 1px dotted #8b949e; cursor: help;">completed</span></span>
                    </div>
                    <div class="progress-bar color-coded">
                        <div class="progress-segment impl-test" style="width: {impl_test_pct:.1f}%" title="Implementation + Test: {stats['implementation_and_test']}"></div>
                        <div class="progress-segment implication" style="width: {implication_pct:.1f}%" title="Implication: {stats['implication_count']}"></div>
                        <div class="progress-segment exception" style="width: {exception_pct:.1f}%" title="Exception: {stats['exception_count']}"></div>
                        <div class="progress-segment impl-only" style="width: {impl_only_pct:.1f}%" title="Implementation Only: {stats['implementation_only']}"></div>
                        <div class="progress-segment no-impl" style="width: {no_impl_pct:.1f}%" title="No Implementation: {stats['no_implementation']}"></div>
                    </div>
                </div>
            </div>
            
            <div class="breakdown-grid single-row">
                <div class="breakdown-item clickable-filter" data-filter="impl-test" onclick="filterRequirements('impl-test')" title="Click to filter Implementation + Test requirements">
                    <div class="breakdown-number" style="color: #28a745;">{stats['implementation_and_test']}</div>
                    <div class="breakdown-label" style="color: #28a745;">Implementation + Test</div>
                </div>
                <div class="breakdown-item clickable-filter" data-filter="implication" onclick="filterRequirements('implication')" title="Click to filter Implication requirements">
                    <div class="breakdown-number" style="color: #dda0dd;">{stats['implication_count']}</div>
                    <div class="breakdown-label" style="color: #dda0dd;">Implication</div>
                </div>
                <div class="breakdown-item clickable-filter" data-filter="exception" onclick="filterRequirements('exception')" title="Click to filter Exception requirements">
                    <div class="breakdown-number" style="color: #87ceeb;">{stats['exception_count']}</div>
                    <div class="breakdown-label" style="color: #87ceeb;">Exception</div>
                </div>
                <div class="breakdown-item clickable-filter" data-filter="impl-only" onclick="filterRequirements('impl-only')" title="Click to filter Implementation Only requirements">
                    <div class="breakdown-number" style="color: #ffc107;">{stats['implementation_only']}</div>
                    <div class="breakdown-label" style="color: #ffc107;">Implementation Only</div>
                </div>
                <div class="breakdown-item clickable-filter" data-filter="none" onclick="filterRequirements('none')" title="Click to filter No Implementation requirements">
                    <div class="breakdown-number" style="color: #dc3545;">{stats['no_implementation']}</div>
                    <div class="breakdown-label" style="color: #dc3545;">No Implementation</div>
                </div>
                <div class="breakdown-item" title="Total requirements count">
                    <div class="breakdown-number" style="color: #8b949e;">{stats['total_requirements']}</div>
                    <div class="breakdown-label" style="color: #8b949e;">Total</div>
                </div>
            </div>
        </div>
    """

    # Generate content for each specification
    spec_counter = 0

    for spec_title, spec_data in specifications.items():
        status_icon = get_spec_status(spec_data)
        sections = spec_data.get("sections", {})

        # Calculate requirement-level progress for this spec
        spec_total_requirements = 0
        spec_complete_requirements = 0

        for section_data in sections.values():
            section_requirements = section_data.get("requirements", [])
            spec_total_requirements += len(section_requirements)
            spec_complete_requirements += sum(
                1 for req in section_requirements if req["is_complete"]
            )

        # Determine alternating background class
        row_class = "even" if spec_counter % 2 == 0 else "odd"
        spec_counter += 1

        # Generate spec-specific URL
        spec_url = generate_spec_url(duvet_report_path, spec_data["spec_path"])

        # Calculate spec-level statistics
        spec_impl_test = 0
        spec_implication = 0
        spec_exception = 0
        spec_impl_only = 0
        spec_no_impl = 0
        
        for section_data in sections.values():
            section_requirements = section_data.get('requirements', [])
            for req in section_requirements:
                if req['has_implementation'] and req['has_test']:
                    spec_impl_test += 1
                elif req['has_implication']:
                    spec_implication += 1
                elif req['has_exception']:
                    spec_exception += 1
                elif req['has_implementation']:
                    spec_impl_only += 1
                else:
                    spec_no_impl += 1
        
        # Calculate percentages for spec progress bar
        if spec_total_requirements > 0:
            spec_impl_test_pct = (spec_impl_test / spec_total_requirements) * 100
            spec_implication_pct = (spec_implication / spec_total_requirements) * 100
            spec_exception_pct = (spec_exception / spec_total_requirements) * 100
            spec_impl_only_pct = (spec_impl_only / spec_total_requirements) * 100
            spec_no_impl_pct = (spec_no_impl / spec_total_requirements) * 100
        else:
            spec_impl_test_pct = spec_implication_pct = spec_exception_pct = spec_impl_only_pct = spec_no_impl_pct = 0

        content_html += f"""
        <div class="spec-section {row_class}">
            <div class="spec-header" onclick="toggleSection('{spec_title.replace(' ', '_')}')">
                <div class="spec-title">
                    <span class="status-emoji">{status_icon}</span>
                    <span>{spec_title}</span>
                    <span class="completion-count">({spec_complete_requirements}/{spec_total_requirements} completed)</span>
                    <a href="{spec_url}" target="_blank" title="View {spec_title} specification in duvet report" style="margin-left: 10px; font-size: 12px; color: #666;">🔗</a>
                </div>
                <span class="expand-icon" id="icon_{spec_title.replace(' ', '_')}">▼</span>
            </div>
            <div class="spec-progress" id="progress_{spec_title.replace(' ', '_')}" style="display: none; padding: 8px 20px; background: #0d1117;">
                <div class="progress-bar color-coded" style="height: 8px;">
                    <div class="progress-segment impl-test" style="width: {spec_impl_test_pct:.1f}%" title="Implementation + Test: {spec_impl_test}"></div>
                    <div class="progress-segment implication" style="width: {spec_implication_pct:.1f}%" title="Implication: {spec_implication}"></div>
                    <div class="progress-segment exception" style="width: {spec_exception_pct:.1f}%" title="Exception: {spec_exception}"></div>
                    <div class="progress-segment impl-only" style="width: {spec_impl_only_pct:.1f}%" title="Implementation Only: {spec_impl_only}"></div>
                    <div class="progress-segment no-impl" style="width: {spec_no_impl_pct:.1f}%" title="No Implementation: {spec_no_impl}"></div>
                </div>
                <div class="spec-breakdown" style="display: flex; justify-content: center; gap: 15px; margin-top: 8px; font-size: 11px; color: #8b949e;">
                    <span style="color: #28a745;">Impl+Test: {spec_impl_test}</span>
                    <span style="color: #dda0dd;">Implication: {spec_implication}</span>
                    <span style="color: #87ceeb;">Exception: {spec_exception}</span>
                    <span style="color: #ffc107;">Impl Only: {spec_impl_only}</span>
                    <span style="color: #dc3545;">None: {spec_no_impl}</span>
                </div>
            </div>
            <div class="spec-content" id="content_{spec_title.replace(' ', '_')}">
"""

        # Add sections within each specification
        for section_title, section_data in sections.items():
            section_requirements = section_data.get("requirements", [])
            section_complete = sum(1 for req in section_requirements if req["is_complete"])
            section_total = len(section_requirements)

            # Skip sections with no requirements at all
            if section_total == 0:
                continue

            # Determine section status using the corrected logic
            # Get individual requirement statuses
            req_statuses = [get_requirement_status(req) for req in section_requirements]

            if all(status == "✅" for status in req_statuses):
                section_status = "✅"  # All requirements are green
            elif any(status in ["✅", "🟡"] for status in req_statuses):
                section_status = "🟡"  # Any requirement is green or yellow
            else:
                section_status = "❌"  # All requirements are red X

            section_id = f"{spec_title.replace(' ', '_')}_{section_title.replace(' ', '_').replace('#', '').replace('-', '_')}"

            # Generate section-specific URL
            section_url = generate_section_url(
                duvet_report_path, spec_data["spec_path"], section_data["section_id"]
            )

            # Generate local file path for this section
            local_file_path = f"{spec_data['spec_path']}#{section_data['section_id']}"

            # Calculate section-level statistics
            section_impl_test = sum(1 for req in section_requirements if req['has_implementation'] and req['has_test'])
            section_implication = sum(1 for req in section_requirements if req['has_implication'])
            section_exception = sum(1 for req in section_requirements if req['has_exception'])
            section_impl_only = sum(1 for req in section_requirements if req['has_implementation'] and not req['has_test'] and not req['has_exception'] and not req['has_implication'])
            section_no_impl = sum(1 for req in section_requirements if not req['has_implementation'] and not req['has_test'] and not req['has_exception'] and not req['has_implication'])
            
            # Calculate percentages for section progress bar
            if section_total > 0:
                section_impl_test_pct = (section_impl_test / section_total) * 100
                section_implication_pct = (section_implication / section_total) * 100
                section_exception_pct = (section_exception / section_total) * 100
                section_impl_only_pct = (section_impl_only / section_total) * 100
                section_no_impl_pct = (section_no_impl / section_total) * 100
            else:
                section_impl_test_pct = section_implication_pct = section_exception_pct = section_impl_only_pct = section_no_impl_pct = 0
            
            content_html += f"""
                <div class="section-item">
                    <div class="section-header" onclick="toggleSubSection('{section_id}')">
                        <div class="section-title">
                            <span class="status-emoji">{section_status}</span>
                            <span>{section_title}</span>
                            <span class="completion-count">({section_complete}/{section_total} completed)</span>
                            <a href="{section_url}" target="_blank" title="View {section_title} section in duvet report" style="margin-left: 8px; font-size: 11px; color: #888;">🔗</a>
                        </div>
                        <span class="expand-icon" id="icon_{section_id}">▼</span>
                    </div>
                    <div class="section-content" id="content_{section_id}">
                        <div class="section-progress" id="section_progress_{section_id}" style="display: none; padding: 8px 15px; background: #1a1f26; margin-bottom: 10px;">
                            <div class="progress-bar color-coded" style="height: 6px;">
                                <div class="progress-segment impl-test" style="width: {section_impl_test_pct:.1f}%" title="Implementation + Test: {section_impl_test}"></div>
                                <div class="progress-segment implication" style="width: {section_implication_pct:.1f}%" title="Implication: {section_implication}"></div>
                                <div class="progress-segment exception" style="width: {section_exception_pct:.1f}%" title="Exception: {section_exception}"></div>
                                <div class="progress-segment impl-only" style="width: {section_impl_only_pct:.1f}%" title="Implementation Only: {section_impl_only}"></div>
                                <div class="progress-segment no-impl" style="width: {section_no_impl_pct:.1f}%" title="No Implementation: {section_no_impl}"></div>
                            </div>
                            <div class="section-breakdown" style="display: flex; justify-content: center; gap: 12px; margin-top: 6px; font-size: 10px; color: #8b949e;">
                                <span style="color: #28a745;">Impl+Test: {section_impl_test}</span>
                                <span style="color: #dda0dd;">Implication: {section_implication}</span>
                                <span style="color: #87ceeb;">Exception: {section_exception}</span>
                                <span style="color: #ffc107;">Impl Only: {section_impl_only}</span>
                                <span style="color: #dc3545;">None: {section_no_impl}</span>
                            </div>
                        </div>
                        <div class="section-filepath" style="font-size: 11px; color: #a0aec0; margin-bottom: 10px; font-family: monospace; background: #2d3748; padding: 4px 8px; border-radius: 3px;">
                            <span>{local_file_path}</span>
                            <button onclick="copyToClipboard('//= {local_file_path}')" style="background: #4a5568; color: #a0aec0; border: none; padding: 2px 6px; border-radius: 2px; font-size: 10px; cursor: pointer; margin-left: 8px;" title="Copy with //= prefix">📋</button>
                        </div>
"""

            # Add requirements within each section
            req_counter = 1
            for requirement in section_requirements:
                req_status = get_requirement_status(requirement)
                req_text = format_requirement_text(requirement["text"])

                # Build detailed source information with GitHub links - one bullet per source
                sources_html = ""
                if requirement["related_sources"]:
                    source_bullets = []
                    for source_info in requirement["related_sources"]:
                        source_type = source_info["type"]
                        source_path = source_info["source"]
                        line_num = source_info["line"]

                        # Generate GitHub URL if possible
                        github_url = generate_github_url(source_path, line_num, github_base_url)

                        if github_url and source_path.endswith(".go"):
                            # Create clickable link for Go source files
                            source_display = f'<a href="{github_url}" target="_blank" style="color: #0366d6; text-decoration: none;">{source_path}'
                            if line_num:
                                source_display += f":{line_num}"
                            source_display += "</a>"
                        else:
                            # Plain text for non-Go files or when no GitHub URL
                            source_display = source_path
                            if line_num:
                                source_display += f":{line_num}"

                        type_display = source_type.lower()
                        # Add partial indicator if this requirement has partial coverage
                        if requirement.get("has_partial_coverage", False):
                            type_display = f"partial {type_display}"
                        source_bullets.append(f"• {type_display}: {source_display}")

                    sources_html = (
                        '<div class="requirement-sources" style="font-size: 11px; color: #666; margin-top: 4px;">'
                        + "<br>".join(source_bullets)
                        + "</div>"
                    )
                else:
                    sources_html = '<div class="requirement-sources" style="font-size: 11px; color: #999; margin-top: 4px;">• no implementation found</div>'

                # Determine requirement type for filtering
                if requirement["has_exception"]:
                    req_type = "exception"
                elif requirement["has_implication"]:
                    req_type = "implication"
                elif requirement["has_implementation"] and requirement["has_test"] and not requirement.get("has_partial_coverage", False):
                    req_type = "impl-test"
                elif requirement["has_implementation"] and not requirement.get("has_partial_coverage", False):
                    req_type = "impl-only"
                else:
                    # Partial coverage and no implementation both get "none" type
                    req_type = "none"

                # Prepare requirement text for copying (clean version without HTML)
                clean_req_text = requirement["text"].replace("\n", " ").strip()
                # Escape single quotes for JavaScript
                clean_req_text = clean_req_text.replace("'", "\\'")
                copy_text = f"//# {clean_req_text}"

                content_html += f"""
                        <div class="requirement-item" data-requirement-type="{req_type}">
                            <div class="requirement-header">
                                <span class="requirement-id">Requirement {req_counter}:</span>
                                <span class="requirement-status">{req_status}</span>
                                <button onclick="copyToClipboard('{copy_text}')" style="background: #4a5568; color: #a0aec0; border: none; padding: 1px 4px; border-radius: 2px; font-size: 9px; cursor: pointer; margin-left: 6px;" title="Copy requirement with //# prefix">📋</button>
                            </div>
                            <div class="requirement-text">{req_text}</div>
                            {sources_html}
                        </div>
"""
                req_counter += 1

            content_html += """
                    </div>
                </div>
"""

        content_html += """
            </div>
        </div>
"""

    # Replace placeholders in template
    html_content = template.format(server_name=server_name, content=content_html)

    # Write the HTML file
    with open(output_file_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_server_report(server_path, server_name):
    """Generate individual server report using the enhanced report-based format."""
    report_file = server_path / ".duvet" / "reports" / "report.html"

    if not report_file.exists():
        return None

    try:
        # Parse the report directly
        specifications = parse_report_html(report_file)

        # Generate the enhanced HTML report
        html_output_file = server_path / "compliance_summary_report.html"
        generate_enhanced_html_report(report_file, html_output_file, server_name)

        # Calculate detailed statistics
        stats = calculate_summary_statistics(specifications)

        # Calculate overall status based on actual implementation progress
        total_reqs = stats.get("total_requirements", 0)
        complete_reqs = stats.get("complete_requirements", 0)

        if total_reqs == 0:
            overall_status = "❌"  # No requirements means not compliant
        elif complete_reqs == total_reqs:
            overall_status = "✅"  # All requirements complete
        elif complete_reqs > 0:
            overall_status = "🟡"  # Some requirements complete
        else:
            overall_status = "❌"  # No requirements complete

        # Calculate spec-level status
        spec_statuses = {}
        for spec_title, spec_data in specifications.items():
            spec_statuses[spec_title] = get_spec_status(spec_data)

        total_specs = len(specifications)
        complete_specs = sum(1 for status in spec_statuses.values() if status == "✅")

        return {
            "name": server_name,
            "status": overall_status,
            "total_specs": total_specs,
            "complete_specs": complete_specs,
            "total_sections": stats["total_sections"],
            "complete_sections": stats["complete_sections"],
            "total_requirements": stats["total_requirements"],
            "complete_requirements": stats["complete_requirements"],
            "report_file": f"../{server_name}/compliance_summary_report.html",
            "specifications": spec_statuses,
            "stats": stats,  # Include full stats for homepage display
        }

    except Exception as e:
        print(f"Error processing {server_name}: {e}")
        return None


def generate_expected_output(report_file_path, output_file_path):
    """Generate the expected output format from report.html."""
    specifications = parse_report_html(report_file_path)

    output_lines = []
    for spec_title, spec_data in specifications.items():
        status_icon = get_spec_status(spec_data)
        output_lines.append(f"{spec_title}: {status_icon}")

    # Write the output file
    with open(output_file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines))


def generate_stats_output(report_file_path, output_file_path):
    """Generate detailed statistics output for dashboard use."""
    specifications = parse_report_html(report_file_path)
    stats = calculate_summary_statistics(specifications)

    # Write stats as JSON for easy parsing
    import json

    with open(output_file_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)


def generate_homepage(servers_info, output_file):
    """Generate the main homepage with links to all server reports using templates."""

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Load the homepage template
    template_dir = Path(__file__).parent / "templates"
    template = load_template(template_dir / "homepage_template.html")

    content_html = ""

    if servers_info:
        # Calculate overall statistics
        total_servers = len(servers_info)
        compliant_servers = sum(1 for server in servers_info if server["status"] == "✅")
        partial_servers = sum(1 for server in servers_info if server["status"] == "🟡")
        non_compliant_servers = sum(1 for server in servers_info if server["status"] == "❌")

        # Add compact dark mode summary header
        content_html += f"""
        <div class="summary-header" style="background: #2d3748; padding: 12px 20px; border-radius: 6px; margin-bottom: 20px; text-align: center;">
            <div style="display: flex; justify-content: center; gap: 30px; flex-wrap: wrap;">
                <div class="summary-stat">
                    <span style="font-size: 18px; font-weight: bold; color: #a0aec0;">{total_servers}</span>
                    <div style="font-size: 12px; color: #718096;">Total</div>
                </div>
                <div class="summary-stat">
                    <span style="font-size: 18px; font-weight: bold; color: #48bb78;">{compliant_servers}</span>
                    <div style="font-size: 12px; color: #718096;">Compliant</div>
                </div>
                <div class="summary-stat">
                    <span style="font-size: 18px; font-weight: bold; color: #ed8936;">{partial_servers}</span>
                    <div style="font-size: 12px; color: #718096;">Partial</div>
                </div>
                <div class="summary-stat">
                    <span style="font-size: 18px; font-weight: bold; color: #f56565;">{non_compliant_servers}</span>
                    <div style="font-size: 12px; color: #718096;">Missing</div>
                </div>
            </div>
        </div>
        
        <div class="servers-grid">
"""

        # Generate server cards with detailed statistics
        for server in sorted(servers_info, key=lambda x: x["name"]):
            # Get detailed stats for this server
            server_stats = server.get("stats", {})

            # Calculate percentages for each implementation type
            total_reqs = server_stats.get("total_requirements", 0)
            if total_reqs > 0:
                # Calculate raw percentages
                impl_test_pct = (server_stats.get("implementation_and_test", 0) / total_reqs) * 100
                impl_only_pct = (server_stats.get("implementation_only", 0) / total_reqs) * 100
                test_only_pct = (server_stats.get("test_only", 0) / total_reqs) * 100
                exception_pct = (server_stats.get("exception_count", 0) / total_reqs) * 100
                implication_pct = (server_stats.get("implication_count", 0) / total_reqs) * 100
                no_impl_pct = (server_stats.get("no_implementation", 0) / total_reqs) * 100
                
                # Ensure percentages add up to exactly 100% by using precise calculation
                if total_reqs > 0:
                    # Calculate exact percentages and distribute remainder to largest segment
                    percentages_data = [
                        (server_stats.get("implementation_and_test", 0), 'impl_test'),
                        (server_stats.get("implication_count", 0), 'implication'),
                        (server_stats.get("exception_count", 0), 'exception'),
                        (server_stats.get("implementation_only", 0), 'impl_only'),
                        (server_stats.get("no_implementation", 0), 'no_impl')
                    ]
                    
                    # Calculate percentages with high precision, then distribute remainder
                    total_allocated = 0.0
                    calculated_percentages = {}
                    
                    # Calculate all but the last percentage
                    for i, (count, name) in enumerate(percentages_data[:-1]):
                        pct = round((count / total_reqs) * 100, 1)
                        calculated_percentages[name] = pct
                        total_allocated += pct
                    
                    # Last segment gets the remainder to ensure exactly 100%
                    last_count, last_name = percentages_data[-1]
                    calculated_percentages[last_name] = round(100.0 - total_allocated, 1)
                    
                    # Assign back to variables
                    impl_test_pct = calculated_percentages['impl_test']
                    implication_pct = calculated_percentages['implication']
                    exception_pct = calculated_percentages['exception']
                    impl_only_pct = calculated_percentages['impl_only']
                    no_impl_pct = calculated_percentages['no_impl']
            else:
                impl_test_pct = impl_only_pct = test_only_pct = exception_pct = implication_pct = (
                    no_impl_pct
                ) = 0

            content_html += f"""
            <div class="server-card">
                <div class="server-header">
                    <div class="server-name">{server['name']}</div>
                    <div class="server-status">{server['status']}</div>
                </div>
                <div class="server-body">
                    <div class="progress-item">
                        <div class="progress-header">
                            <span class="progress-label">Requirements Progress</span>
                            <span class="progress-count">{server_stats.get('complete_requirements', 0)}/{server_stats.get('total_requirements', 0)} completed</span>
                        </div>
                        <div class="progress-bar color-coded">
                            <div class="progress-segment impl-test" style="width: {impl_test_pct:.1f}%" title="Implementation + Test: {server_stats.get('implementation_and_test', 0)}"></div>
                            <div class="progress-segment implication" style="width: {implication_pct:.1f}%" title="Implication: {server_stats.get('implication_count', 0)}"></div>
                            <div class="progress-segment exception" style="width: {exception_pct:.1f}%" title="Exception: {server_stats.get('exception_count', 0)}"></div>
                            <div class="progress-segment impl-only" style="width: {impl_only_pct:.1f}%" title="Implementation Only: {server_stats.get('implementation_only', 0)}"></div>
                            <div class="progress-segment no-impl" style="width: {no_impl_pct:.1f}%" title="No Implementation: {server_stats.get('no_implementation', 0)}"></div>
                        </div>
                    </div>
                    
                    <div class="breakdown-grid single-row">
                        <div class="breakdown-item">
                            <div class="breakdown-number" style="color: #28a745;">{server_stats.get('implementation_and_test', 0)}</div>
                            <div class="breakdown-label" style="color: #28a745;">Impl+Test</div>
                        </div>
                        <div class="breakdown-item">
                            <div class="breakdown-number" style="color: #dda0dd;">{server_stats.get('implication_count', 0)}</div>
                            <div class="breakdown-label" style="color: #dda0dd;">Implication</div>
                        </div>
                        <div class="breakdown-item">
                            <div class="breakdown-number" style="color: #87ceeb;">{server_stats.get('exception_count', 0)}</div>
                            <div class="breakdown-label" style="color: #87ceeb;">Exception</div>
                        </div>
                        <div class="breakdown-item">
                            <div class="breakdown-number" style="color: #ffc107;">{server_stats.get('implementation_only', 0)}</div>
                            <div class="breakdown-label" style="color: #ffc107;">Impl Only</div>
                        </div>
                        <div class="breakdown-item">
                            <div class="breakdown-number" style="color: #dc3545;">{server_stats.get('no_implementation', 0)}</div>
                            <div class="breakdown-label" style="color: #dc3545;">None</div>
                        </div>
                        <div class="breakdown-item">
                            <div class="breakdown-number" style="color: #8b949e;">{server_stats.get('total_requirements', 0)}</div>
                            <div class="breakdown-label" style="color: #8b949e;">Total</div>
                        </div>
                    </div>
                </div>
                <div class="server-footer">
                    <a href="{server['report_file']}" class="view-report-btn">View Detailed Report</a>
                </div>
            </div>
"""

        content_html += """
        </div>
"""
    else:
        content_html += """
        <div class="no-servers">
            <p>No servers with compliance reports found.</p>
            <p>Make sure servers have .duvet/reports/report.html files.</p>
        </div>
"""

    # Replace placeholders in template
    html_content = template.format(timestamp=current_time, content=content_html)

    # Write the HTML file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)


def discover_servers():
    """Discover all servers with .duvet/reports/report.html files."""
    servers_info = []
    # Get the test-server directory (parent of spec-compliance-dashboard)
    test_server_dir = Path(__file__).parent.parent

    # Look for directories with .duvet/reports/report.html
    for item in test_server_dir.iterdir():
        if item.is_dir() and not item.name.startswith(".") and item.name != "spec-compliance-dashboard":
            duvet_report = item / ".duvet" / "reports" / "report.html"
            if duvet_report.exists():
                server_info = generate_server_report(item, item.name)
                if server_info:
                    servers_info.append(server_info)
                    print(f"Processed server: {item.name}")

    return servers_info


def main():
    """Main function to generate both individual server reports and dashboard."""
    import sys

    # Check if server directory is provided as argument (for single server mode)
    if len(sys.argv) > 1:
        server_dir = Path(sys.argv[1])
        server_name = sys.argv[2] if len(sys.argv) > 2 else server_dir.name

        report_file = server_dir / ".duvet" / "reports" / "report.html"
        html_output_file = server_dir / "compliance_summary_report.html"
        expected_output_file = server_dir / "expected_output_report.txt"

        if not report_file.exists():
            print(f"Error: Report file not found at {report_file}")
            return 1

        try:
            # Generate HTML report
            generate_enhanced_html_report(report_file, html_output_file, server_name)
            print(f"Interactive HTML report generated: {html_output_file}")

            # Generate expected output
            generate_expected_output(report_file, expected_output_file)
            print(f"Expected output generated: {expected_output_file}")

            # Generate stats output for dashboard
            stats_output_file = server_dir / "compliance_stats.json"
            generate_stats_output(report_file, stats_output_file)
            print(f"Stats output generated: {stats_output_file}")

            return 0
        except Exception as e:
            print(f"Error generating reports: {e}")
            return 1
    else:
        # Dashboard mode - discover all servers and generate dashboard
        try:
            print("Discovering servers with compliance reports...")
            servers_info = discover_servers()

            if servers_info:
                print(f"Found {len(servers_info)} servers with reports")

                # Generate the main dashboard homepage
                homepage_file = Path(__file__).parent / "compliance_homepage.html"
                generate_homepage(servers_info, homepage_file)
                print(f"Dashboard homepage generated: {homepage_file}")

                return 0
            else:
                print("No servers with .duvet/reports/report.html found")
                return 1

        except Exception as e:
            print(f"Error generating dashboard: {e}")
            return 1


if __name__ == "__main__":
    exit(main())
