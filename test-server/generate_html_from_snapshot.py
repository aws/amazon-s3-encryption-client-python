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

def generate_html_report(snapshot_file_path, output_file_path, server_name):
    """Generate an interactive HTML report."""
    specifications = parse_snapshot(snapshot_file_path)
    
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{server_name} - Duvet Compliance Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #0d1117;
            color: #c9d1d9;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: #161b22;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            border: 1px solid #30363d;
            overflow: hidden;
        }
        .header {
            background: #21262d;
            color: #c9d1d9;
            padding: 8px 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #30363d;
        }
        .header h1 {
            margin: 0;
            font-size: 1.2em;
            font-weight: 500;
        }
        .nav-link {
            color: white;
            text-decoration: none;
            font-size: 0.9em;
            opacity: 0.9;
        }
        .nav-link:hover {
            opacity: 1;
            text-decoration: underline;
        }
        .spec-section {
            border-bottom: 1px solid #30363d;
        }
        .spec-section.even {
            background: #161b22;
        }
        .spec-section.odd {
            background: #0d1117;
        }
        .spec-header {
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: transparent;
            transition: background-color 0.2s;
            color: #c9d1d9;
        }
        .spec-header:hover {
            background: #21262d;
        }
        .spec-title {
            font-size: 18px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .completion-count {
            color: #8b949e;
            font-size: 0.8em;
            font-weight: 400;
        }
        .status-emoji {
            font-size: 20px;
        }
        .expand-icon {
            font-size: 14px;
            transition: transform 0.2s;
        }
        .spec-content {
            display: none;
            padding: 20px;
            background: transparent;
        }
        .spec-content.expanded {
            display: block;
        }
        .requirement-item {
            margin-bottom: 15px;
            padding: 15px;
            background: #161b22;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            border: 1px solid #30363d;
            color: #c9d1d9;
        }
        .requirement-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            color: #c9d1d9;
        }
        .requirement-id {
            font-weight: bold;
            color: #c9d1d9;
        }
        .requirement-status {
            font-size: 16px;
        }
        .requirement-text {
            color: #c9d1d9;
            white-space: pre-wrap;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 14px;
            line-height: 1.4;
        }
        .section-item {
            margin-bottom: 10px;
            border-radius: 6px;
            background: #21262d;
            border: 1px solid #30363d;
        }
        .section-header {
            padding: 12px 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: transparent;
            transition: background-color 0.2s;
            color: #c9d1d9;
        }
        .section-header:hover {
            background: #30363d;
        }
        .section-title {
            font-size: 16px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .section-content {
            display: none;
            padding: 15px;
            background: transparent;
        }
        .section-content.expanded {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{server_name}</h1>
            <a href="../compliance_homepage.html" class="nav-link">Back to Homepage</a>
        </div>
""".format(server_name=server_name)
    
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
