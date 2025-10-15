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
    
    # Generate summary statistics HTML
    content_html = f"""
        <div class="summary-stats">
            <h2>Summary Statistics</h2>
            <div class="progress-section">
                <div class="progress-item">
                    <div class="progress-header">
                        <span class="progress-label">Sections Implemented</span>
                        <span class="progress-count">{stats['complete_sections']}/{stats['total_sections']}</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {section_progress:.1f}%"></div>
                    </div>
                </div>
                <div class="progress-item">
                    <div class="progress-header">
                        <span class="progress-label">Requirements Implemented</span>
                        <span class="progress-count">{stats['complete_requirements']}/{stats['total_requirements']}</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {requirement_progress:.1f}%"></div>
                    </div>
                </div>
            </div>
            
            <div class="breakdown-header" onclick="togglePieChart()">
                <h3>Implementation Breakdown</h3>
                <span class="expand-icon" id="pie-chart-icon">▼</span>
            </div>
            <div class="breakdown-grid">
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['implementation_and_test']}</div>
                    <div class="breakdown-label" style="color: #28a745;">Implementation + Test</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['implementation_only']}</div>
                    <div class="breakdown-label" style="color: #ffc107;">Implementation Only</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['test_only']}</div>
                    <div class="breakdown-label">Test Only</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['exception_count']}</div>
                    <div class="breakdown-label" style="color: #87ceeb;">Exception</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['implication_count']}</div>
                    <div class="breakdown-label" style="color: #dda0dd;">Implication</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['no_implementation']}</div>
                    <div class="breakdown-label" style="color: #dc3545;">No Implementation</div>
                </div>
            </div>
            
            <div class="pie-chart-container" id="pie-chart-container" style="display: none;">
                <canvas id="implementationPieChart" width="250" height="250"></canvas>
            </div>
            
            <script>
                function togglePieChart() {{
                    const container = document.getElementById('pie-chart-container');
                    const icon = document.getElementById('pie-chart-icon');
                    
                    if (container.style.display === 'none') {{
                        container.style.display = 'flex';
                        icon.textContent = '▲';
                        drawPieChart();
                    }} else {{
                        container.style.display = 'none';
                        icon.textContent = '▼';
                    }}
                }}
                
                function drawPieChart() {{
                    const canvas = document.getElementById('implementationPieChart');
                    const ctx = canvas.getContext('2d');
                    const centerX = canvas.width / 2;
                    const centerY = canvas.height / 2;
                    const radius = 100;
                    
                    // Clear canvas
                    ctx.clearRect(0, 0, canvas.width, canvas.height);
                    
                    const data = [
                        {{ label: 'Implementation + Test', value: {stats['implementation_and_test']}, color: '#28a745' }},
                        {{ label: 'Implementation Only', value: {stats['implementation_only']}, color: '#ffc107' }},
                        {{ label: 'Exception', value: {stats['exception_count']}, color: '#87ceeb' }},
                        {{ label: 'Implication', value: {stats['implication_count']}, color: '#dda0dd' }},
                        {{ label: 'No Implementation', value: {stats['no_implementation']}, color: '#dc3545' }}
                    ];
                    
                    // Filter out zero values
                    const filteredData = data.filter(item => item.value > 0);
                    const total = filteredData.reduce((sum, item) => sum + item.value, 0);
                    
                    if (total > 0) {{
                        let currentAngle = -Math.PI / 2; // Start at top
                        
                        // Draw pie slices
                        filteredData.forEach(item => {{
                            const sliceAngle = (item.value / total) * 2 * Math.PI;
                            
                            ctx.beginPath();
                            ctx.moveTo(centerX, centerY);
                            ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
                            ctx.closePath();
                            ctx.fillStyle = item.color;
                            ctx.fill();
                            ctx.strokeStyle = '#fff';
                            ctx.lineWidth = 2;
                            ctx.stroke();
                            
                            // Draw label if slice is large enough
                            if (item.value / total > 0.05) {{
                                const labelAngle = currentAngle + sliceAngle / 2;
                                const labelX = centerX + Math.cos(labelAngle) * (radius * 0.7);
                                const labelY = centerY + Math.sin(labelAngle) * (radius * 0.7);
                                
                                ctx.fillStyle = '#fff';
                                ctx.font = 'bold 12px Arial';
                                ctx.textAlign = 'center';
                                ctx.fillText(item.value.toString(), labelX, labelY);
                            }}
                            
                            currentAngle += sliceAngle;
                        }});
                    }} else {{
                        // Draw "No data" message
                        ctx.fillStyle = '#666';
                        ctx.font = '16px Arial';
                        ctx.textAlign = 'center';
                        ctx.fillText('No data available', centerX, centerY);
                    }}
                }}
            </script>
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
        
        content_html += f"""
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
        # Calculate overall stats
        total_servers = len(servers_info)
        complete_servers = sum(1 for server in servers_info if server['status'] == '✅')
        partial_servers = sum(1 for server in servers_info if server['status'] == '🟡')
        
        content_html += f"""
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
            
            content_html += f"""
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
