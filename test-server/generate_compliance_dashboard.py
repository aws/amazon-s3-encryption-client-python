#!/usr/bin/env python3
"""
Comprehensive script to generate compliance dashboard and all server reports.
Automatically discovers servers with .duvet/reports/report.html files and generates
individual reports using the enhanced report-based format.
"""

import re
import os
import json
from pathlib import Path
from datetime import datetime

# Import functions from the report generator
from generate_html_from_report import (
    parse_report_html,
    calculate_summary_statistics,
    generate_html_report as generate_enhanced_html_report,
    get_spec_status
)

def parse_snapshot(snapshot_file_path):
    """Parse the snapshot.txt file and extract specification data."""
    with open(snapshot_file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    specifications = {}
    current_spec = None
    current_section = None
    
    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
            
        if line.startswith('SPECIFICATION:'):
            # Extract specification title
            match = re.search(r'SPECIFICATION: \[([^\]]+)\]', line)
            if match:
                spec_title = match.group(1)
                current_spec = {
                    'title': spec_title,
                    'sections': {}
                }
                specifications[spec_title] = current_spec
                
        elif line.startswith('SECTION:'):
            # Extract section title
            match = re.search(r'SECTION: \[([^\]]+)\]', line)
            if match and current_spec:
                section_title = match.group(1)
                current_section = {
                    'title': section_title,
                    'requirements': []
                }
                current_spec['sections'][section_title] = current_section
                
        elif line.startswith('TEXT['):
            # Extract requirement information
            if current_section:
                # Parse the TEXT[...] format to extract status indicators
                match = re.search(r'TEXT\[([^\]]+)\]:\s*(.*)', line)
                if match:
                    status_part = match.group(1)
                    text_part = match.group(2)
                    
                    # Parse status indicators
                    has_implementation = 'implementation' in status_part
                    has_test = 'test' in status_part
                    has_exception = 'exception' in status_part
                    has_implication = 'implication' in status_part
                    
                    # Determine completion status based on the rules:
                    # Complete = (implementation AND test) OR exception OR implication
                    is_complete = (has_implementation and has_test) or has_exception or has_implication
                    
                    requirement = {
                        'text': text_part,
                        'has_implementation': has_implementation,
                        'has_test': has_test,
                        'has_exception': has_exception,
                        'has_implication': has_implication,
                        'is_complete': is_complete
                    }
                    current_section['requirements'].append(requirement)
    
    return specifications

def get_requirement_status(requirement):
    """Get the status emoji for a single requirement."""
    if requirement['is_complete']:
        return '✅'
    elif requirement['has_implementation']:
        return '🟡'  # Has implementation but no test
    else:
        return '❌'  # No implementation

def get_spec_status(spec_data):
    """Determine the overall status of a specification based on all its sections."""
    sections = spec_data.get('sections', {})
    
    if not sections:
        return '✅'  # No sections means complete
    
    # Get status of each section using corrected logic
    section_statuses = []
    for section_data in sections.values():
        requirements = section_data.get('requirements', [])
        if not requirements:
            section_statuses.append('✅')  # Empty section is complete
        else:
            # Get individual requirement statuses
            req_statuses = []
            for req in requirements:
                if req['is_complete']:
                    req_statuses.append('✅')
                elif req['has_implementation']:
                    req_statuses.append('🟡')
                else:
                    req_statuses.append('❌')
            
            if all(status == '✅' for status in req_statuses):
                section_statuses.append('✅')  # All requirements are green
            elif any(status in ['✅', '🟡'] for status in req_statuses):
                section_statuses.append('🟡')  # Any requirement is green or yellow
            else:
                section_statuses.append('❌')  # All requirements are red X
    
    # Apply the corrected logic based on section statuses:
    if all(status == '✅' for status in section_statuses):
        return '✅'  # Green check if all sections are green
    elif any(status in ['✅', '🟡'] for status in section_statuses):
        return '🟡'  # Yellow if any section is green or yellow
    else:
        return '❌'  # Red X if all sections are red X

def get_overall_server_status(specifications):
    """Get overall status for a server based on all its specifications."""
    if not specifications:
        return '❌'
    
    statuses = [get_spec_status(spec_data) for spec_data in specifications.values()]
    
    if all(status == '✅' for status in statuses):
        return '✅'
    elif any(status in ['✅', '🟡'] for status in statuses):
        return '🟡'
    else:
        return '❌'

def generate_server_report(server_path, server_name):
    """Generate individual server report using the enhanced report-based format."""
    report_file = server_path / '.duvet' / 'reports' / 'report.html'
    
    if not report_file.exists():
        return None
    
    try:
        # Parse the report directly using imported function
        specifications = parse_report_html(report_file)
        
        # Generate the enhanced HTML report
        html_output_file = server_path / 'compliance_summary_report.html'
        generate_enhanced_html_report(report_file, html_output_file, server_name)
        
        # Calculate detailed statistics
        stats = calculate_summary_statistics(specifications)
        
        # Calculate overall status based on actual implementation progress
        total_reqs = stats.get('total_requirements', 0)
        complete_reqs = stats.get('complete_requirements', 0)
        
        if total_reqs == 0:
            overall_status = '❌'  # No requirements means not compliant
        elif complete_reqs == total_reqs:
            overall_status = '✅'  # All requirements complete
        elif complete_reqs > 0:
            overall_status = '🟡'  # Some requirements complete
        else:
            overall_status = '❌'  # No requirements complete
        
        # Calculate spec-level status
        spec_statuses = {}
        for spec_title, spec_data in specifications.items():
            spec_statuses[spec_title] = get_spec_status(spec_data)
        
        total_specs = len(specifications)
        complete_specs = sum(1 for status in spec_statuses.values() if status == '✅')
        
        return {
            'name': server_name,
            'status': overall_status,
            'total_specs': total_specs,
            'complete_specs': complete_specs,
            'total_sections': stats['total_sections'],
            'complete_sections': stats['complete_sections'],
            'total_requirements': stats['total_requirements'],
            'complete_requirements': stats['complete_requirements'],
            'report_file': f'{server_name}/compliance_summary_report.html',
            'specifications': spec_statuses,
            'stats': stats  # Include full stats for homepage display
        }
        
    except Exception as e:
        print(f"Error processing {server_name}: {e}")
        return None

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
    
    for spec_data in specifications.values():
        sections = spec_data.get('sections', {})
        total_sections += len(sections)
        
        for section_data in sections.values():
            requirements = section_data.get('requirements', [])
            total_requirements += len(requirements)
            
            # Count complete requirements
            section_complete_reqs = sum(1 for req in requirements if req['is_complete'])
            complete_requirements += section_complete_reqs
            
            # A section is complete if all its requirements are complete
            if requirements and section_complete_reqs == len(requirements):
                complete_sections += 1
            elif not requirements:  # Empty section is considered complete
                complete_sections += 1
            
            # Count requirements by implementation type
            for req in requirements:
                if req['has_exception']:
                    exception_count += 1
                elif req['has_implication']:
                    implication_count += 1
                elif req['has_implementation'] and req['has_test']:
                    implementation_and_test += 1
                elif req['has_implementation']:
                    implementation_only += 1
                elif req['has_test']:
                    test_only += 1
                else:
                    no_implementation += 1
    
    return {
        'total_sections': total_sections,
        'complete_sections': complete_sections,
        'total_requirements': total_requirements,
        'complete_requirements': complete_requirements,
        'no_implementation': no_implementation,
        'implementation_only': implementation_only,
        'test_only': test_only,
        'implementation_and_test': implementation_and_test,
        'exception_count': exception_count,
        'implication_count': implication_count
    }

def load_template(template_path):
    """Load a template file."""
    with open(template_path, 'r', encoding='utf-8') as f:
        return f.read()

def generate_html_report(specifications, output_file_path, server_name):
    """Generate an interactive HTML report for a server using templates."""
    
    # Load the report template
    template_dir = Path(__file__).parent / 'templates'
    template = load_template(template_dir / 'report_template.html')
    
    # Calculate summary statistics
    stats = calculate_summary_statistics(specifications)
    
    # Calculate progress percentages
    section_progress = (stats['complete_sections'] / stats['total_sections'] * 100) if stats['total_sections'] > 0 else 0
    requirement_progress = (stats['complete_requirements'] / stats['total_requirements'] * 100) if stats['total_requirements'] > 0 else 0
    
    # Calculate percentages for each implementation type
    total_reqs = stats['total_requirements']
    if total_reqs > 0:
        impl_test_pct = (stats['implementation_and_test'] / total_reqs) * 100
        impl_only_pct = (stats['implementation_only'] / total_reqs) * 100
        test_only_pct = (stats['test_only'] / total_reqs) * 100
        exception_pct = (stats['exception_count'] / total_reqs) * 100
        implication_pct = (stats['implication_count'] / total_reqs) * 100
        no_impl_pct = (stats['no_implementation'] / total_reqs) * 100
    else:
        impl_test_pct = impl_only_pct = test_only_pct = exception_pct = implication_pct = no_impl_pct = 0

    # Generate summary statistics HTML with color-coded progress bars
    content_html = f"""
        <div class="summary-stats">
            <div class="progress-section">
                <div class="progress-item">
                    <div class="progress-header">
                        <span class="progress-label">Requirements by Implementation Type</span>
                        <span class="progress-count">{stats['complete_requirements']}/{stats['total_requirements']}</span>
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
            
            <div class="breakdown-grid">
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['implementation_and_test']}</div>
                    <div class="breakdown-label" style="color: #28a745;">Implementation + Test</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['implication_count']}</div>
                    <div class="breakdown-label" style="color: #dda0dd;">Implication</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['exception_count']}</div>
                    <div class="breakdown-label" style="color: #87ceeb;">Exception</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['implementation_only']}</div>
                    <div class="breakdown-label" style="color: #ffc107;">Implementation Only</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['no_implementation']}</div>
                    <div class="breakdown-label" style="color: #dc3545;">No Implementation</div>
                </div>
            </div>
        </div>
    """
    
    # Generate content for each specification
    spec_counter = 0
    for spec_title, spec_data in specifications.items():
        status_icon = get_spec_status(spec_data)
        sections = spec_data.get('sections', {})
        
        # Calculate requirement-level progress for this spec
        spec_total_requirements = 0
        spec_complete_requirements = 0
        
        for section_data in sections.values():
            section_requirements = section_data.get('requirements', [])
            spec_total_requirements += len(section_requirements)
            spec_complete_requirements += sum(1 for req in section_requirements if req['is_complete'])
        
        # Determine alternating background class
        row_class = "even" if spec_counter % 2 == 0 else "odd"
        spec_counter += 1
        
        content_html += f"""
        <div class="spec-section {row_class}">
            <div class="spec-header" onclick="toggleSection('{spec_title.replace(' ', '_')}')">
                <div class="spec-title">
                    <span class="status-emoji">{status_icon}</span>
                    <span>{spec_title}</span>
                    <span class="completion-count">({spec_complete_requirements}/{spec_total_requirements})</span>
                </div>
                <span class="expand-icon" id="icon_{spec_title.replace(' ', '_')}">▼</span>
            </div>
            <div class="spec-content" id="content_{spec_title.replace(' ', '_')}">
"""
        
        # Add sections within each specification
        for section_title, section_data in sections.items():
            section_requirements = section_data.get('requirements', [])
            section_complete = sum(1 for req in section_requirements if req['is_complete'])
            section_total = len(section_requirements)
            
            # Determine section status using the corrected logic
            if not section_requirements:
                section_status = '✅'  # Empty section is complete
            else:
                # Get individual requirement statuses
                req_statuses = [get_requirement_status(req) for req in section_requirements]
                
                if all(status == '✅' for status in req_statuses):
                    section_status = '✅'  # All requirements are green
                elif any(status in ['✅', '🟡'] for status in req_statuses):
                    section_status = '🟡'  # Any requirement is green or yellow
                else:
                    section_status = '❌'  # All requirements are red X
            
            section_id = f"{spec_title.replace(' ', '_')}_{section_title.replace(' ', '_').replace('#', '').replace('-', '_')}"
            
            content_html += f"""
                <div class="section-item">
                    <div class="section-header" onclick="toggleSubSection('{section_id}')">
                        <div class="section-title">
                            <span class="status-emoji">{section_status}</span>
                            <span>{section_title}</span>
                            <span class="completion-count">({section_complete}/{section_total})</span>
                        </div>
                        <span class="expand-icon" id="icon_{section_id}">▼</span>
                    </div>
                    <div class="section-content" id="content_{section_id}">
"""
            
            # Add requirements within each section
            req_counter = 1
            for requirement in section_requirements:
                req_status = get_requirement_status(requirement)
                req_text = requirement['text']
                
                # Build metadata tags
                metadata_tags = []
                if requirement['has_implementation']:
                    metadata_tags.append('implementation')
                if requirement['has_test']:
                    metadata_tags.append('test')
                if requirement['has_exception']:
                    metadata_tags.append('exception')
                if requirement['has_implication']:
                    metadata_tags.append('implication')
                
                metadata_text = ', '.join(metadata_tags) if metadata_tags else 'no implementation'
                
                content_html += f"""
                        <div class="requirement-item">
                            <div class="requirement-header">
                                <span class="requirement-id">Requirement {req_counter}:</span>
                                <span class="requirement-status">{req_status}</span>
                            </div>
                            <div class="requirement-text">{req_text}</div>
                            <div class="requirement-metadata">Status: {metadata_text}</div>
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
    html_content = template.format(
        server_name=server_name,
        content=content_html
    )
    
    # Write the HTML file
    with open(output_file_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def generate_homepage(servers_info, output_file):
    """Generate the main homepage with links to all server reports using templates."""
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Load the homepage template
    template_dir = Path(__file__).parent / 'templates'
    template = load_template(template_dir / 'homepage_template.html')
    
    content_html = ""
    
    if servers_info:
        # Calculate overall statistics
        total_servers = len(servers_info)
        compliant_servers = sum(1 for server in servers_info if server['status'] == '✅')
        partial_servers = sum(1 for server in servers_info if server['status'] == '🟡')
        non_compliant_servers = sum(1 for server in servers_info if server['status'] == '❌')
        
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
        for server in sorted(servers_info, key=lambda x: x['name']):
            # Get detailed stats for this server
            server_stats = server.get('stats', {})
            
            # Calculate percentages for each implementation type
            total_reqs = server_stats.get('total_requirements', 0)
            if total_reqs > 0:
                impl_test_pct = (server_stats.get('implementation_and_test', 0) / total_reqs) * 100
                impl_only_pct = (server_stats.get('implementation_only', 0) / total_reqs) * 100
                test_only_pct = (server_stats.get('test_only', 0) / total_reqs) * 100
                exception_pct = (server_stats.get('exception_count', 0) / total_reqs) * 100
                implication_pct = (server_stats.get('implication_count', 0) / total_reqs) * 100
                no_impl_pct = (server_stats.get('no_implementation', 0) / total_reqs) * 100
            else:
                impl_test_pct = impl_only_pct = test_only_pct = exception_pct = implication_pct = no_impl_pct = 0
            
            content_html += f"""
            <div class="server-card">
                <div class="server-header">
                    <div class="server-name">{server['name']}</div>
                    <div class="server-status">{server['status']}</div>
                </div>
                <div class="server-body">
                    <div class="progress-item">
                        <div class="progress-header">
                            <span class="progress-label">Requirements by Implementation Type</span>
                            <span class="progress-count">{server_stats.get('complete_requirements', 0)}/{server_stats.get('total_requirements', 0)}</span>
                        </div>
                        <div class="progress-bar color-coded">
                            <div class="progress-segment impl-test" style="width: {impl_test_pct:.1f}%" title="Implementation + Test: {server_stats.get('implementation_and_test', 0)}"></div>
                            <div class="progress-segment implication" style="width: {implication_pct:.1f}%" title="Implication: {server_stats.get('implication_count', 0)}"></div>
                            <div class="progress-segment exception" style="width: {exception_pct:.1f}%" title="Exception: {server_stats.get('exception_count', 0)}"></div>
                            <div class="progress-segment impl-only" style="width: {impl_only_pct:.1f}%" title="Implementation Only: {server_stats.get('implementation_only', 0)}"></div>
                            <div class="progress-segment no-impl" style="width: {no_impl_pct:.1f}%" title="No Implementation: {server_stats.get('no_implementation', 0)}"></div>
                        </div>
                    </div>
                    <div class="server-summary">
                        <div class="summary-row">
                            <div class="summary-item">
                                <span class="summary-number" style="color: #28a745;">{server_stats.get('implementation_and_test', 0)}</span>
                                <span class="summary-label">Complete</span>
                            </div>
                            <div class="summary-item">
                                <span class="summary-number" style="color: #dda0dd;">{server_stats.get('implication_count', 0)}</span>
                                <span class="summary-label">Implied</span>
                            </div>
                            <div class="summary-item">
                                <span class="summary-number" style="color: #87ceeb;">{server_stats.get('exception_count', 0)}</span>
                                <span class="summary-label">Exception</span>
                            </div>
                        </div>
                        <div class="summary-row">
                            <div class="summary-item">
                                <span class="summary-number" style="color: #ffc107;">{server_stats.get('implementation_only', 0)}</span>
                                <span class="summary-label">Partial</span>
                            </div>
                            <div class="summary-item">
                                <span class="summary-number" style="color: #dc3545;">{server_stats.get('no_implementation', 0)}</span>
                                <span class="summary-label">Missing</span>
                            </div>
                            <div class="summary-item">
                                <span class="summary-number" style="color: #8b949e;">{server_stats.get('total_requirements', 0)}</span>
                                <span class="summary-label">Total</span>
                            </div>
                        </div>
                    </div>
                    <a href="{server['report_file']}" class="view-report-btn">View Detailed Report</a>
                </div>
            </div>
"""
        
        content_html += """
        </div>
"""
    else:
        content_html += """
        <div class="no-data">
            <h2>No compliance data found</h2>
            <p>No servers with .duvet/snapshot.txt files were found in the test-server directory.</p>
        </div>
"""
    
    # Replace placeholders in template
    html_content = template.format(
        timestamp=current_time,
        content=content_html
    )
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def main():
    """Main function to generate homepage and all server reports."""
    test_server_dir = Path(__file__).parent
    
    print("Scanning for servers with compliance data...")
    
    servers_info = []
    
    # Scan all subdirectories for .duvet/reports/report.html files
    for item in test_server_dir.iterdir():
        if item.is_dir() and not item.name.startswith('.'):
            report_file = item / '.duvet' / 'reports' / 'report.html'
            if report_file.exists():
                print(f"Processing {item.name}...")
                server_info = generate_server_report(item, item.name)
                if server_info:
                    servers_info.append(server_info)
    
    # Generate homepage
    homepage_file = test_server_dir / 'compliance_homepage.html'
    generate_homepage(servers_info, homepage_file)
    
    print(f"\nGenerated reports for {len(servers_info)} servers:")
    for server in servers_info:
        print(f"  - {server['name']}: {server['status']} ({server['complete_specs']}/{server['total_specs']} specs complete)")
    
    print(f"\nHomepage generated: {homepage_file}")
    print(f"Open {homepage_file} in your browser to view the dashboard.")
    
    return 0

if __name__ == '__main__':
    exit(main())
