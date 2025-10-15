#!/usr/bin/env python3
"""
Script to generate an interactive HTML report from duvet snapshot.txt.
Shows each section with emoji status and expandable sub-requirements.
Uses snapshot.txt as the authoritative source.
"""

import re
from pathlib import Path

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

def get_spec_status(spec_data):
    """Determine the overall status of a specification based on all its sections."""
    sections = spec_data.get('sections', {})
    
    if not sections:
        return '✅'  # No sections means complete
    
    # Get status of each section
    section_statuses = []
    for section_data in sections.values():
        requirements = section_data.get('requirements', [])
        if not requirements:
            section_statuses.append('✅')  # Empty section is complete
        else:
            complete_reqs = sum(1 for req in requirements if req['is_complete'])
            total_reqs = len(requirements)
            
            if complete_reqs == total_reqs:
                section_statuses.append('✅')  # All requirements complete
            elif complete_reqs > 0:
                section_statuses.append('🟡')  # Some requirements complete
            else:
                section_statuses.append('❌')  # No requirements complete
    
    # Apply the corrected logic based on section statuses:
    if all(status == '✅' for status in section_statuses):
        return '✅'  # Green check if all sections are green
    elif any(status in ['✅', '🟡'] for status in section_statuses):
        return '🟡'  # Yellow if any section is green or yellow
    else:
        return '❌'  # Red X if all sections are red X

def get_requirement_status(requirement):
    """Get the status emoji for a single requirement."""
    if requirement['is_complete']:
        return '✅'
    elif requirement['has_implementation']:
        return '🟡'  # Has implementation but no test
    else:
        return '❌'  # No implementation

def format_requirement_text(text):
    """Format requirement text to style status metadata lines."""
    lines = text.split('\n')
    formatted_lines = []
    
    for line in lines:
        # Check if line contains status metadata
        if line.strip().startswith('Status:'):
            formatted_lines.append(f'<span class="status-metadata">{line}</span>')
        else:
            formatted_lines.append(line)
    
    return '\n'.join(formatted_lines)

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

def generate_html_report(snapshot_file_path, output_file_path, server_name):
    """Generate an interactive HTML report using templates."""
    specifications = parse_snapshot(snapshot_file_path)
    
    # Load the report template
    template_dir = Path(__file__).parent / 'templates'
    template = load_template(template_dir / 'report_template.html')
    
    # Calculate summary statistics
    stats = calculate_summary_statistics(specifications)
    
    # Generate summary statistics HTML
    content_html = f"""
        <div class="summary-stats">
            <h2>Summary Statistics</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-number">{stats['complete_sections']}/{stats['total_sections']}</div>
                    <div class="stat-label">Sections Implemented</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{stats['complete_requirements']}/{stats['total_requirements']}</div>
                    <div class="stat-label">Requirements Implemented</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{stats['complete_requirements']/stats['total_requirements']*100:.1f}%</div>
                    <div class="stat-label">Overall Progress</div>
                </div>
            </div>
            
            <h3>Implementation Breakdown</h3>
            <div class="breakdown-grid">
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['implementation_and_test']}</div>
                    <div class="breakdown-label">Implementation + Test</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['implementation_only']}</div>
                    <div class="breakdown-label">Implementation Only</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['test_only']}</div>
                    <div class="breakdown-label">Test Only</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['exception_count']}</div>
                    <div class="breakdown-label">Exception</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['implication_count']}</div>
                    <div class="breakdown-label">Implication</div>
                </div>
                <div class="breakdown-item">
                    <div class="breakdown-number">{stats['no_implementation']}</div>
                    <div class="breakdown-label">No Implementation</div>
                </div>
            </div>
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
                req_text = format_requirement_text(requirement['text'])
                
                content_html += f"""
                        <div class="requirement-item">
                            <div class="requirement-header">
                                <span class="requirement-id">Requirement {req_counter}:</span>
                                <span class="requirement-status">{req_status}</span>
                            </div>
                            <div class="requirement-text">{req_text}</div>
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

def generate_expected_output(snapshot_file_path, output_file_path):
    """Generate the expected output format from snapshot.txt."""
    specifications = parse_snapshot(snapshot_file_path)
    
    output_lines = []
    for spec_title, spec_data in specifications.items():
        status_icon = get_spec_status(spec_data)
        output_lines.append(f"{spec_title}: {status_icon}")
    
    # Write the output file
    with open(output_file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))

def main():
    """Main function to generate both HTML report and expected output."""
    import sys
    
    # Check if server directory is provided as argument
    if len(sys.argv) > 1:
        server_dir = Path(sys.argv[1])
        server_name = sys.argv[2] if len(sys.argv) > 2 else server_dir.name
    else:
        # Default to current directory (for backward compatibility)
        server_dir = Path(__file__).parent
        server_name = "go-v4-server"  # Default name for backward compatibility
    
    snapshot_file = server_dir / '.duvet' / 'snapshot.txt'
    html_output_file = server_dir / 'compliance_summary_snapshot.html'
    expected_output_file = server_dir / 'expected_output.txt'
    
    if not snapshot_file.exists():
        print(f"Error: Snapshot file not found at {snapshot_file}")
        return 1
    
    try:
        # Generate HTML report
        generate_html_report(snapshot_file, html_output_file, server_name)
        print(f"Interactive HTML report generated: {html_output_file}")
        
        # Generate expected output
        generate_expected_output(snapshot_file, expected_output_file)
        print(f"Expected output generated: {expected_output_file}")
        
        return 0
    except Exception as e:
        print(f"Error generating reports: {e}")
        return 1

if __name__ == '__main__':
    exit(main())
