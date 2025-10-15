#!/usr/bin/env python3
"""
Comprehensive script to generate compliance dashboard and all server reports.
Automatically discovers servers with .duvet/snapshot.txt files and generates
individual reports using the snapshot-based format with GitHub color scheme.
"""

import re
import os
from pathlib import Path
from datetime import datetime

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
    """Generate individual server report using snapshot-based format."""
    snapshot_file = server_path / '.duvet' / 'snapshot.txt'
    
    if not snapshot_file.exists():
        return None
    
    # Parse the snapshot
    specifications = parse_snapshot(snapshot_file)
    
    # Generate expected output
    output_lines = []
    for spec_title, spec_data in specifications.items():
        status_icon = get_spec_status(spec_data)
        output_lines.append(f"{spec_title}: {status_icon}")
    
    # Write expected output
    expected_output_file = server_path / 'expected_output.txt'
    with open(expected_output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))
    
    # Generate HTML report
    html_output_file = server_path / 'compliance_summary_snapshot.html'
    generate_html_report(specifications, html_output_file, server_name)
    
    # Calculate detailed compliance metrics
    overall_status = get_overall_server_status(specifications)
    total_specs = len(specifications)
    complete_specs = sum(1 for spec_data in specifications.values() 
                        if get_spec_status(spec_data) == '✅')
    
    # Calculate section and requirement level metrics
    total_sections = 0
    complete_sections = 0
    total_requirements = 0
    complete_requirements = 0
    
    for spec_data in specifications.values():
        sections = spec_data.get('sections', {})
        total_sections += len(sections)
        
        for section_data in sections.values():
            requirements = section_data.get('requirements', [])
            total_requirements += len(requirements)
            complete_requirements += sum(1 for req in requirements if req['is_complete'])
            
            # A section is complete if all its requirements are complete
            if requirements and all(req['is_complete'] for req in requirements):
                complete_sections += 1
    
    return {
        'name': server_name,
        'status': overall_status,
        'total_specs': total_specs,
        'complete_specs': complete_specs,
        'total_sections': total_sections,
        'complete_sections': complete_sections,
        'total_requirements': total_requirements,
        'complete_requirements': complete_requirements,
        'report_file': f'{server_name}/compliance_summary_snapshot.html',
        'specifications': specifications
    }

def generate_html_report(specifications, output_file_path, server_name):
    """Generate an interactive HTML report for a server using GitHub color scheme."""
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{server_name} - Duvet Compliance Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #0d1117;
            color: #c9d1d9;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: #161b22;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            border: 1px solid #30363d;
            overflow: hidden;
        }}
        .header {{
            background: #21262d;
            color: #c9d1d9;
            padding: 8px 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #30363d;
        }}
        .header h1 {{
            margin: 0;
            font-size: 1.2em;
            font-weight: 500;
        }}
        .nav-link {{
            color: white;
            text-decoration: none;
            font-size: 0.9em;
            opacity: 0.9;
        }}
        .nav-link:hover {{
            opacity: 1;
            text-decoration: underline;
        }}
        .spec-section {{
            border-bottom: 1px solid #30363d;
        }}
        .spec-section.even {{
            background: #161b22;
        }}
        .spec-section.odd {{
            background: #0d1117;
        }}
        .spec-header {{
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: transparent;
            transition: background-color 0.2s;
            color: #c9d1d9;
        }}
        .spec-header:hover {{
            background: #21262d;
        }}
        .spec-title {{
            font-size: 18px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .completion-count {{
            color: #8b949e;
            font-size: 0.8em;
            font-weight: 400;
        }}
        .status-emoji {{
            font-size: 20px;
        }}
        .expand-icon {{
            font-size: 14px;
            transition: transform 0.2s;
        }}
        .spec-content {{
            display: none;
            padding: 20px;
            background: transparent;
        }}
        .spec-content.expanded {{
            display: block;
        }}
        .requirement-item {{
            margin-bottom: 15px;
            padding: 15px;
            background: #161b22;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            border: 1px solid #30363d;
            color: #c9d1d9;
        }}
        .requirement-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            color: #c9d1d9;
        }}
        .requirement-id {{
            font-weight: bold;
            color: #c9d1d9;
        }}
        .requirement-status {{
            font-size: 16px;
        }}
        .requirement-text {{
            color: #c9d1d9;
            white-space: pre-wrap;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 14px;
            line-height: 1.4;
        }}
        .section-item {{
            margin-bottom: 10px;
            border-radius: 6px;
            background: #21262d;
            border: 1px solid #30363d;
        }}
        .section-header {{
            padding: 12px 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: transparent;
            transition: background-color 0.2s;
            color: #c9d1d9;
        }}
        .section-header:hover {{
            background: #30363d;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .section-content {{
            display: none;
            padding: 15px;
            background: transparent;
        }}
        .section-content.expanded {{
            display: block;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{server_name}</h1>
            <a href="../compliance_homepage.html" class="nav-link">Back to Homepage</a>
        </div>
"""
    
    # Generate content for each specification
    spec_counter = 0
    for spec_title, spec_data in specifications.items():
        status_icon = get_spec_status(spec_data)
        sections = spec_data.get('sections', {})
        
        # Calculate section-level progress for this spec
        total_sections = len(sections)
        complete_sections = 0
        
        for section_data in sections.values():
            section_requirements = section_data.get('requirements', [])
            if section_requirements:
                section_complete = sum(1 for req in section_requirements if req['is_complete'])
                section_total = len(section_requirements)
                # A section is considered complete if all its requirements are complete
                if section_complete == section_total:
                    complete_sections += 1
            else:
                # Empty section is considered complete
                complete_sections += 1
        
        # Determine alternating background class
        row_class = "even" if spec_counter % 2 == 0 else "odd"
        spec_counter += 1
        
        html_content += f"""
        <div class="spec-section {row_class}">
            <div class="spec-header" onclick="toggleSection('{spec_title.replace(' ', '_')}')">
                <div class="spec-title">
                    <span class="status-emoji">{status_icon}</span>
                    <span>{spec_title}</span>
                    <span class="completion-count">({complete_sections}/{total_sections})</span>
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
            
            html_content += f"""
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
                
                html_content += f"""
                        <div class="requirement-item">
                            <div class="requirement-header">
                                <span class="requirement-id">Requirement {req_counter}:</span>
                                <span class="requirement-status">{req_status}</span>
                            </div>
                            <div class="requirement-text">{req_text}</div>
                        </div>
"""
                req_counter += 1
            
            html_content += """
                    </div>
                </div>
"""
        
        html_content += """
            </div>
        </div>
"""
    
    # Add JavaScript and closing HTML
    html_content += """
    </div>
    
    <script>
        function toggleSection(sectionId) {
            const content = document.getElementById('content_' + sectionId);
            const icon = document.getElementById('icon_' + sectionId);
            
            if (content.classList.contains('expanded')) {
                content.classList.remove('expanded');
                icon.textContent = '▼';
            } else {
                content.classList.add('expanded');
                icon.textContent = '▲';
            }
        }
        
        function toggleSubSection(sectionId) {
            const content = document.getElementById('content_' + sectionId);
            const icon = document.getElementById('icon_' + sectionId);
            
            if (content.classList.contains('expanded')) {
                content.classList.remove('expanded');
                icon.textContent = '▼';
            } else {
                content.classList.add('expanded');
                icon.textContent = '▲';
            }
        }
        
        // Add keyboard navigation
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                // Close all expanded sections and subsections
                document.querySelectorAll('.spec-content.expanded').forEach(content => {
                    content.classList.remove('expanded');
                });
                document.querySelectorAll('.section-content.expanded').forEach(content => {
                    content.classList.remove('expanded');
                });
                document.querySelectorAll('.expand-icon').forEach(icon => {
                    icon.textContent = '▼';
                });
            }
        });
    </script>
</body>
</html>
"""
    
    # Write the HTML file
    with open(output_file_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def generate_homepage(servers_info, output_file):
    """Generate the main homepage with links to all server reports."""
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Spec Compliance Dashboard</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #0d1117;
            color: #c9d1d9;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #161b22;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            border: 1px solid #30363d;
            overflow: hidden;
        }}
        .header {{
            background: #21262d;
            color: #c9d1d9;
            padding: 15px 20px;
            text-align: center;
            border-bottom: 1px solid #30363d;
        }}
        .header h1 {{
            margin: 0;
            font-size: 1.8em;
            font-weight: 400;
        }}
        .header p {{
            margin: 5px 0 0 0;
            opacity: 0.9;
            font-size: 0.9em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #0d1117;
        }}
        .stat-card {{
            background: #161b22;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            border: 1px solid #30363d;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #c9d1d9;
        }}
        .stat-label {{
            color: #8b949e;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .servers-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
            padding: 30px;
        }}
        .server-card {{
            background: #161b22;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            border: 1px solid #30363d;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .server-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 3px 6px rgba(0,0,0,0.4);
        }}
        .server-header {{
            padding: 12px 16px;
            background: #21262d;
            color: #c9d1d9;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #30363d;
        }}
        .server-name {{
            font-size: 1.2em;
            font-weight: 600;
        }}
        .server-status {{
            font-size: 1.5em;
        }}
        .server-body {{
            padding: 20px;
        }}
        .progress-bar {{
            background: #0d1117;
            border-radius: 6px;
            height: 8px;
            margin: 15px 0;
            overflow: hidden;
            border: 1px solid #30363d;
        }}
        .progress-fill {{
            height: 100%;
            background: #238636;
            border-radius: 6px;
            transition: width 0.3s ease;
        }}
        .server-stats {{
            display: flex;
            justify-content: space-between;
            margin-top: 15px;
            font-size: 0.9em;
            color: #8b949e;
        }}
        .view-report-btn {{
            display: inline-block;
            margin-top: 15px;
            padding: 10px 20px;
            background: #238636;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            transition: background-color 0.2s;
        }}
        .view-report-btn:hover {{
            background: #2ea043;
        }}
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #8b949e;
        }}
        .footer {{
            padding: 20px;
            text-align: center;
            background: #21262d;
            color: #8b949e;
            font-size: 0.9em;
            border-top: 1px solid #30363d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Spec Compliance Dashboard</h1>
            <p>Last updated: {current_time}</p>
        </div>
"""
    
    if servers_info:
        # Calculate overall stats
        total_servers = len(servers_info)
        complete_servers = sum(1 for server in servers_info if server['status'] == '✅')
        partial_servers = sum(1 for server in servers_info if server['status'] == '🟡')
        
        html_content += f"""
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{total_servers}</div>
                <div class="stat-label">Total Servers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{complete_servers}</div>
                <div class="stat-label">Fully Compliant</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{partial_servers}</div>
                <div class="stat-label">Partially Compliant</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{complete_servers}/{total_servers}</div>
                <div class="stat-label">Servers Complete</div>
            </div>
        </div>
        
        <div class="servers-grid">
"""
        
        # Generate server cards
        for server in sorted(servers_info, key=lambda x: x['name']):
            spec_progress_percent = (server['complete_specs'] / server['total_specs'] * 100) if server['total_specs'] > 0 else 0
            section_progress_percent = (server['complete_sections'] / server['total_sections'] * 100) if server['total_sections'] > 0 else 0
            requirement_progress_percent = (server['complete_requirements'] / server['total_requirements'] * 100) if server['total_requirements'] > 0 else 0
            
            html_content += f"""
            <div class="server-card">
                <div class="server-header">
                    <div class="server-name">{server['name']}</div>
                    <div class="server-status">{server['status']}</div>
                </div>
                <div class="server-body">
                    <div style="margin-bottom: 10px;">
                        <div style="font-size: 0.9em; color: #8b949e; margin-bottom: 5px;">Specification Compliance: {spec_progress_percent:.1f}%</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {spec_progress_percent:.1f}%"></div>
                        </div>
                    </div>
                    <div style="margin-bottom: 10px;">
                        <div style="font-size: 0.9em; color: #8b949e; margin-bottom: 5px;">Section Compliance: {section_progress_percent:.1f}%</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {section_progress_percent:.1f}%"></div>
                        </div>
                    </div>
                    <div style="margin-bottom: 15px;">
                        <div style="font-size: 0.9em; color: #8b949e; margin-bottom: 5px;">Requirement Compliance: {requirement_progress_percent:.1f}%</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {requirement_progress_percent:.1f}%"></div>
                        </div>
                    </div>
                    <div class="server-stats">
                        <span>{server['complete_specs']}/{server['total_specs']} specs</span>
                        <span>{server['complete_sections']}/{server['total_sections']} sections</span>
                        <span>{server['complete_requirements']}/{server['total_requirements']} reqs</span>
                    </div>
                    <a href="{server['report_file']}" class="view-report-btn">View Detailed Report</a>
                </div>
            </div>
"""
        
        html_content += """
        </div>
"""
    else:
        html_content += """
        <div class="no-data">
            <h2>No compliance data found</h2>
            <p>No servers with .duvet/snapshot.txt files were found in the test-server directory.</p>
        </div>
"""
    
    html_content += f"""
        <div class="footer">
            Generated by duvet compliance dashboard • {current_time}
        </div>
    </div>
</body>
</html>
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def main():
    """Main function to generate homepage and all server reports."""
    test_server_dir = Path(__file__).parent
    
    print("Scanning for servers with compliance data...")
    
    servers_info = []
    
    # Scan all subdirectories for .duvet/snapshot.txt files
    for item in test_server_dir.iterdir():
        if item.is_dir() and not item.name.startswith('.'):
            snapshot_file = item / '.duvet' / 'snapshot.txt'
            if snapshot_file.exists():
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
