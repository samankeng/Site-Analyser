# backend/scanner/services/pdf_report_generator.py

import io
import json
import logging
from datetime import datetime, timedelta
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, 
    Image, PageBreak, ListFlowable, ListItem
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend

logger = logging.getLogger(__name__)

class PDFReportGenerator:
    """Generates comprehensive PDF security scan reports with visualizations and detailed findings"""
    
    def __init__(self, scan, results):
        """
        Initialize the report generator
        
        Args:
            scan: The Scan model instance
            results: List of ScanResult model instances
        """
        self.scan = scan
        self.results = results
        self.buffer = io.BytesIO()
        
        # Define styles to be used throughout the report
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'Title',
            parent=self.styles['Heading1'],
            fontSize=20,
            alignment=1,  # Center alignment
            spaceAfter=12
        )
        self.section_title_style = ParagraphStyle(
            'SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=12,
            spaceAfter=6
        )
        self.subsection_style = ParagraphStyle(
            'SubSection',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceBefore=10,
            spaceAfter=4
        )
        self.subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceBefore=8,
            spaceAfter=4
        )
        self.normal_style = self.styles['Normal']
        self.cell_style = ParagraphStyle(
            'CellStyle',
            parent=self.styles['Normal'],
            fontSize=10,
            leading=12,
            wordWrap='CJK'  # Enable word wrapping
        )
        self.code_style = ParagraphStyle(
            'Code',
            parent=self.styles['Code'],
            fontSize=8,
            fontName='Courier',
            leading=10
        )
    
    def generate_pdf(self):
        """
        Generate a comprehensive PDF report
        
        Returns:
            BytesIO: Buffer containing the generated PDF
        """
        doc = SimpleDocTemplate(
            self.buffer, 
            pagesize=letter,
            rightMargin=72, 
            leftMargin=72,
            topMargin=72, 
            bottomMargin=72,
            title=f"Security Scan Report - {self.scan.target_url}"
        )
        
        # Container for all 'Flowable' objects
        elements = []
        
        try:
            # Build the report sections
            self._add_cover_page(elements)
            self._add_table_of_contents(elements)
            self._add_executive_summary(elements)
            self._add_scan_details(elements)
            self._add_security_score(elements)
            self._add_vulnerability_summary(elements)
            self._add_detailed_findings(elements)
            self._add_remediation_recommendations(elements)
            
            # Build the PDF with custom footer
            doc.build(elements, onFirstPage=self._add_page_number, onLaterPages=self._add_page_number)
            
        except Exception as e:
            logger.error(f"Error building PDF: {str(e)}")
            # Create a simplified error PDF
            self.buffer = io.BytesIO()
            doc = SimpleDocTemplate(self.buffer, pagesize=letter)
            error_elements = [
                Paragraph(f"Error generating PDF report", self.title_style),
                Spacer(1, 20),
                Paragraph(f"An error occurred while generating the PDF report: {str(e)}", self.normal_style),
                Paragraph(f"Please try again or contact support if the issue persists.", self.normal_style)
            ]
            doc.build(error_elements)
        
        # Get the value of the BytesIO buffer and reset it
        pdf = self.buffer.getvalue()
        self.buffer.seek(0)
        
        return pdf
    
    def _add_cover_page(self, elements):
        """Add a professional cover page to the report"""
        current_date = datetime.now().strftime('%B %d, %Y')
        
        elements.append(Paragraph(current_date, self.normal_style))
        elements.append(Spacer(1, 200))  # Add space
        
        elements.append(Paragraph("Security Scan Report", self.title_style))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"Target: {self.scan.target_url}", self.subtitle_style))
        elements.append(Spacer(1, 20))
        
        elements.append(Paragraph("Prepared By", self.normal_style))
        elements.append(Paragraph("Site-Analyser Security", ParagraphStyle(
            'CompanyName',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceBefore=4
        )))
        
        # Add organization logo placeholder
        # In a real implementation, you'd include your company's logo
        elements.append(Spacer(1, 40))
        
        elements.append(PageBreak())
    
    def _add_vulnerability_summary(self, elements):
        """Add vulnerability summary section with charts and tables"""
        elements.append(Paragraph("4. Vulnerability Summary", self.section_title_style))
        elements.append(Spacer(1, 12))
        
        if self.results:
            # Get scan types from results
            scan_types = set(result.category for result in self.results)
            
            # Count findings by category
            category_counts = {}
            for result in self.results:
                category = result.category
                category_counts[category] = category_counts.get(category, 0) + 1
            
            # Create scan type distribution chart
            if category_counts:
                scan_type_chart = self._create_scan_type_chart(category_counts)
                elements.append(scan_type_chart)
                elements.append(Spacer(1, 20))
            
            # Create a summary table by severity
            elements.append(Paragraph("Summary by Severity", self.subtitle_style))
            elements.append(Spacer(1, 6))
            
            severity_counts = self._get_severity_counts()
            
            summary_data = [["Severity", "Count", "Description"]]
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            
            for severity in severity_order:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    description = {
                        'critical': "Critical issues require immediate attention",
                        'high': "High severity issues should be addressed soon",
                        'medium': "Medium severity issues to fix in regular maintenance",
                        'low': "Low severity issues to address when convenient",
                        'info': "Informational findings for awareness"
                    }.get(severity, "")
                    
                    summary_data.append([severity.capitalize(), str(count), description])
            
            # If there are no findings in one of the categories, add a row saying so
            if not summary_data[1:]:
                summary_data.append(["None", "0", "No vulnerabilities found"])
            
            summary_table = Table(summary_data, colWidths=[1*inch, 0.8*inch, 3.7*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            
            # Add colors to severity cells
            for i, row in enumerate(summary_data[1:], 1):
                severity = row[0].lower()
                color = {
                    'critical': colors.red,
                    'high': colors.orange,
                    'medium': colors.yellowgreen,
                    'low': colors.lightblue,
                    'info': colors.lightgrey,
                    'none': colors.white
                }.get(severity, colors.white)
                
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, i), (0, i), color),
                ]))
            
            elements.append(summary_table)
            
            # Add findings by category
            if category_counts:
                elements.append(Spacer(1, 20))
                elements.append(Paragraph("Summary by Category", self.subtitle_style))
                elements.append(Spacer(1, 6))
                
                # Create category summary table
                category_data = [["Category", "Count", "Description"]]
                
                # Get descriptions for scan types from scan_types.py
                category_descriptions = {
                    'headers': "HTTP security header issues",
                    'ssl': "SSL/TLS configuration issues",
                    'vulnerabilities': "Web application vulnerabilities",
                    'content': "Content and SEO issues",
                    'ports': "Open ports and network services",
                    'csp': "Content Security Policy issues",
                    'cookies': "Cookie security issues",
                    'cors': "Cross-Origin Resource Sharing issues",
                    'server': "Server configuration issues"
                }
                
                for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                    description = category_descriptions.get(category, "Various issues")
                    category_data.append([category.capitalize(), str(count), description])
                
                category_table = Table(category_data, colWidths=[1*inch, 0.8*inch, 3.7*inch])
                category_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                
                elements.append(category_table)
        else:
            elements.append(Paragraph("No vulnerabilities found. Your site passed all security checks!", self.normal_style))
        
        elements.append(PageBreak())
    
    def _add_detailed_findings(self, elements):
        """Add detailed findings section with complete vulnerability information"""
        elements.append(Paragraph("5. Detailed Findings", self.section_title_style))
        elements.append(Spacer(1, 12))
        
        if self.results:
            # Group findings by severity
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            
            for severity in severity_order:
                severity_findings = [r for r in self.results if r.severity == severity]
                
                if severity_findings:
                    elements.append(Paragraph(f"{severity.capitalize()} Severity Findings", self.subsection_style))
                    elements.append(Spacer(1, 6))
                    
                    for i, finding in enumerate(severity_findings):
                        # Format finding details
                        elements.append(Paragraph(f"{i+1}. {self._sanitize_html(finding.name)}", self.subtitle_style))
                        
                        finding_details = [
                            ["Category", finding.category.capitalize()],
                            ["Description", self._sanitize_html(finding.description)],
                        ]
                        
                        # Add details from JSON
                        json_details = finding.details
                        if json_details:
                            # Extract location information
                            if 'page_url' in json_details:
                                finding_details.append(["Location", self._sanitize_html(json_details['page_url'])])
                            
                            # Extract recommendation if available
                            if 'recommendation' in json_details:
                                finding_details.append(["Recommendation", self._sanitize_html(json_details['recommendation'])])
                            
                            # Extract impact if available
                            if 'impact' in json_details:
                                finding_details.append(["Impact", self._sanitize_html(json_details['impact'])])
                            
                            # Add other relevant details
                            for key, value in json_details.items():
                                if key not in ['recommendation', 'impact', 'page_url', 'error', 'form_html', 'details', 'content_preview']:
                                    # Use safe formatting for complex objects
                                    formatted_value = self._format_json_for_pdf(value)
                                    finding_details.append([key.replace('_', ' ').title(), formatted_value])
                        
                        # Create a table for finding details with proper cell wrapping
                        wrapped_details = []
                        for row in finding_details:
                            if len(row) != 2:
                                continue  # Skip invalid rows
                                
                            key, value = row
                            
                            # Handle different value types
                            if isinstance(value, str):
                                # Limit length to prevent oversized cells
                                safe_value = self._sanitize_html(value)
                                if len(safe_value) > 500:
                                    safe_value = safe_value[:500] + "..."
                                    
                                wrapped_details.append([
                                    Paragraph(self._sanitize_html(key), self.cell_style),
                                    Paragraph(safe_value, self.cell_style)
                                ])
                            else:
                                # For complex objects, format them safely
                                try:
                                    if isinstance(value, (dict, list)):
                                        value_str = json.dumps(value, indent=2, default=str)[:500]
                                        wrapped_details.append([
                                            Paragraph(self._sanitize_html(key), self.cell_style),
                                            Paragraph(value_str, self.code_style)
                                        ])
                                    else:
                                        wrapped_details.append([
                                            Paragraph(self._sanitize_html(key), self.cell_style),
                                            Paragraph(str(value), self.cell_style)
                                        ])
                                except Exception:
                                    # If formatting fails, use a simple string
                                    wrapped_details.append([
                                        Paragraph(self._sanitize_html(key), self.cell_style),
                                        Paragraph("[Complex data]", self.cell_style)
                                    ])
                        
                        if wrapped_details:  # Only create table if we have valid details
                            details_table = Table(wrapped_details, colWidths=[1.2*inch, 4.3*inch])
                            details_table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                                ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
                                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                                ('FONTSIZE', (0, 0), (-1, -1), 10),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                                ('TOPPADDING', (0, 0), (-1, -1), 6),
                                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                            ]))
                            
                            elements.append(details_table)
                        elements.append(Spacer(1, 12))
                    
                    elements.append(Spacer(1, 6))
        else:
            elements.append(Paragraph("No vulnerabilities found. Your site passed all security checks!", self.normal_style))
        
        elements.append(PageBreak())
    
    def _add_table_of_contents(self, elements):
        """Add table of contents to the report"""
        elements.append(Paragraph("Table of Contents", self.section_title_style))
        elements.append(Spacer(1, 12))
        
        toc_items = [
            "1. Executive Summary",
            "2. Scan Details",
            "3. Security Score",
            "4. Vulnerability Summary",
            "5. Detailed Findings",
            "6. Remediation Recommendations"
        ]
        
        for item in toc_items:
            elements.append(Paragraph(item, self.normal_style))
            elements.append(Spacer(1, 6))
        
        elements.append(PageBreak())
    
    def _add_executive_summary(self, elements):
        """Add executive summary section with key findings"""
        elements.append(Paragraph("1. Executive Summary", self.section_title_style))
        elements.append(Spacer(1, 12))
        
        # Calculate security findings stats
        severity_counts = self._get_severity_counts()
        total_findings = sum(severity_counts.values())
        security_score = self._calculate_security_score(severity_counts)
        
        summary_text = f"""
        A security scan was performed on {self.scan.target_url} on {self.scan.created_at.strftime('%Y-%m-%d')}.
        The scan identified a total of {total_findings} security findings across {len(self.scan.scan_types)} different scan types.
        
        The overall security score for this site is {security_score}/100, which is considered
        {self._get_risk_level_text(security_score)}.
        """
        elements.append(Paragraph(summary_text, self.normal_style))
        
        # Add key findings to executive summary
        if self.results:
            elements.append(Paragraph("Key findings include:", self.normal_style))
            bullet_items = []
            
            # Critical and high findings first
            critical_high = [r for r in self.results if r.severity in ['critical', 'high']]
            if not critical_high:
                critical_high = [r for r in self.results if r.severity == 'medium'][:3]  # Take some medium if no high/critical
            
            if critical_high:
                for result in critical_high[:5]:  # Limit to top 5
                    bullet_text = f"{result.name} ({result.severity.upper()}) - {self._sanitize_html(result.description[:100])}..."
                    bullet_items.append(ListItem(Paragraph(bullet_text, self.normal_style)))
                    
                bullets = ListFlowable(
                    bullet_items,
                    bulletType='bullet',
                    leftIndent=20
                )
                elements.append(bullets)
            else:
                elements.append(Paragraph("No high or critical security issues were identified.", self.normal_style))
        else:
            elements.append(Paragraph("No security issues were identified during the scan.", self.normal_style))
        
        elements.append(Spacer(1, 12))
        elements.append(PageBreak())
    
    def _add_scan_details(self, elements):
        """Add scan details section with scan configuration"""
        elements.append(Paragraph("2. Scan Details", self.section_title_style))
        elements.append(Spacer(1, 12))
        
        # Format the scan details in a table
        scan_data = [
            ["Target URL", self.scan.target_url],
            ["Status", self.scan.status.upper()],
            ["Created", self.scan.created_at.strftime("%Y-%m-%d %H:%M:%S")],
            ["Completed", self.scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if self.scan.completed_at else "N/A"],
            ["Duration", self._format_duration(self.scan.created_at, self.scan.completed_at) if self.scan.completed_at else "N/A"],
            ["Scan Types", ", ".join(self.scan.scan_types) if self.scan.scan_types else "Full Scan"]
        ]
        
        scan_table = Table(scan_data, colWidths=[1.5*inch, 4*inch])
        scan_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        elements.append(scan_table)
        elements.append(Spacer(1, 12))
        
        # Show errors if any
        if self.scan.error_message:
            elements.append(Paragraph("Scan Errors", self.subtitle_style))
            elements.append(Paragraph(f"The following error occurred during the scan: {self._sanitize_html(self.scan.error_message)}", self.normal_style))
        
        elements.append(PageBreak())
    
    def _add_security_score(self, elements):
        # """Add security score section with score visualization"""
        # elements.append(Paragraph("3. Security Score", self.section_title_style))
        # elements.append(Spacer(1, 12))
        
        # # Create score visualization
        # severity_counts = self._get_severity_counts()
        # security_score = self._calculate_security_score(severity_counts)
        
        # elements.append(Paragraph("Overall Security Score", self.subtitle_style))
        
        """Add security score section with score visualization"""
        elements.append(Paragraph("3. Security Score", self.section_title_style))
        elements.append(Spacer(1, 12))
        
        # Use the scan's security_score if available, otherwise calculate it
        security_score = getattr(self.scan, 'security_score', None)
        if security_score is None:
            # Fall back to calculation if not provided
            severity_counts = self._get_severity_counts()
            security_score = self._calculate_security_score(severity_counts)
        
        elements.append(Paragraph("Overall Security Score", self.subtitle_style))
        
            
        # Add score visualization
        score_visualization = self._create_score_gauge(security_score)
        elements.append(score_visualization)
        elements.append(Spacer(1, 12))
        
        # Add severity distribution
        elements.append(Paragraph("Finding Severity Distribution", self.subtitle_style))
        elements.append(Spacer(1, 6))
        
        # Create severity distribution chart
        severity_chart = self._create_severity_chart(severity_counts)
        elements.append(severity_chart)
        elements.append(Spacer(1, 12))
        
        # Add risk score explanation
        elements.append(Paragraph("Security Score Explanation", self.subtitle_style))
        
        # Calculate severities for explanation
        critical_deduction = severity_counts.get('critical', 0) * 15
        high_deduction = severity_counts.get('high', 0) * 8
        medium_deduction = severity_counts.get('medium', 0) * 4
        low_deduction = severity_counts.get('low', 0) * 1
        total_deduction = critical_deduction + high_deduction + medium_deduction + low_deduction
        
        explanation_text = f"""
        The security score is calculated based on the number and severity of findings:
        - Critical issues: -15 points each
        - High issues: -8 points each
        - Medium issues: -4 points each
        - Low issues: -1 points each
        - Informational: No point deduction
        
        Current score components:
        - Base score: 100
        - Critical issues: {severity_counts.get('critical', 0)} × -15 = {critical_deduction}
        - High issues: {severity_counts.get('high', 0)} × -8 = {high_deduction}
        - Medium issues: {severity_counts.get('medium', 0)} × -4 = {medium_deduction}
        - Low issues: {severity_counts.get('low', 0)} × -1 = {low_deduction}
        - Total deduction: {total_deduction}
        
        Final score: {security_score}/100 - {self._get_risk_level_text(security_score)}
        """
        elements.append(Paragraph(explanation_text, self.normal_style))
        
        elements.append(PageBreak())
    
    def _add_remediation_recommendations(self, elements):
        """Add remediation recommendations section with actionable advice"""
        elements.append(Paragraph("6. Remediation Recommendations", self.section_title_style))
        elements.append(Spacer(1, 12))
        
        if self.results:
            # Group recommendations by category
            categories = set(result.category for result in self.results)
            
            for category in sorted(categories):
                elements.append(Paragraph(f"{category.capitalize()} Recommendations", self.subsection_style))
                elements.append(Spacer(1, 6))
                
                category_findings = [r for r in self.results if r.category == category]
                
                recommendations = []
                for finding in category_findings:
                    if 'recommendation' in finding.details:
                        recommendation = self._sanitize_html(finding.details['recommendation'])
                        severity = finding.severity.upper()
                        name = self._sanitize_html(finding.name)
                        
                        # Include finding name, severity, and recommendation
                        formatted_rec = f"{name} ({severity}): {recommendation}"
                        
                        if formatted_rec not in recommendations:
                            recommendations.append(formatted_rec)
                
                if recommendations:
                    rec_items = []
                    for recommendation in recommendations:
                        rec_items.append(ListItem(Paragraph(recommendation, self.normal_style)))
                    
                    rec_list = ListFlowable(
                        rec_items,
                        bulletType='bullet',
                        leftIndent=20
                    )
                    elements.append(rec_list)
                else:
                    # Generic recommendations if no specific ones are available
                    generic_recs = self._get_generic_recommendations(category)
                    elements.append(Paragraph(generic_recs, self.normal_style))
                
                elements.append(Spacer(1, 10))
        else:
            elements.append(Paragraph("No recommendations necessary as no vulnerabilities were found.", self.normal_style))
    
    def _add_page_number(self, canvas, doc):
        """Add page numbers and date to the footer of each page"""
        canvas.saveState()
        canvas.setFont('Helvetica', 9)
        page_num = f"Page {canvas.getPageNumber()}"
        canvas.drawRightString(letter[0] - 72, 40, page_num)
        canvas.drawString(72, 40, f"Report generated on {datetime.now().strftime('%Y-%m-%d')}")
        canvas.restoreState()
    
    def _get_severity_counts(self):
        """Count findings by severity"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for result in self.results:
            severity = result.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return severity_counts
    
    def _calculate_security_score(self, severity_counts):
        """Calculate security score based on severity counts"""
        severity_weights = {
            'critical': 15,  # Most severe impact
            'high': 8,      # Significant risk
            'medium': 4,     # Moderate concern
            'low': 1,        # Minor issue
            'info': 0        # Informational, no score reduction
        }
        
        # Ensure all severity levels are present with default 0 if not found
        normalized_counts = {
            'critical': severity_counts.get('critical', 0),
            'high': severity_counts.get('high', 0),
            'medium': severity_counts.get('medium', 0),
            'low': severity_counts.get('low', 0),
            'info': severity_counts.get('info', 0)
        }
        
        total_deduction = sum(
            count * severity_weights.get(severity, 0) 
            for severity, count in normalized_counts.items()
        )
        
        # Cap deduction at 100 points, resulting in a minimum score of 0
        return max(0, 100 - min(100, total_deduction))
    
    def _create_score_gauge(self, score):
        """Create a visual gauge for the security score"""
        if score >= 90:
            color = colors.green
            description = "VERY SECURE"
        elif score >= 70:
            color = colors.yellowgreen
            description = "SECURE"
        elif score >= 50:
            color = colors.orange
            description = "NEEDS IMPROVEMENT"
        else:
            color = colors.red
            description = "INSECURE"
        
        data = [["Security Score", "Rating"]]
        data.append([
            Paragraph(f"<font size='24'><b>{score}</b></font>/100", ParagraphStyle(
                'Score', 
                alignment=1,  # Center
                fontSize=24,
            )),
            Paragraph(f"<font size='16'><b>{description}</b></font>", ParagraphStyle(
                'Rating', 
                alignment=1,  # Center
                fontSize=16,
            ))
        ])
        
        score_table = Table(data, colWidths=[2.5*inch, 3*inch], rowHeights=[0.4*inch, 1.2*inch])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('BACKGROUND', (0, 1), (0, 1), color),
            ('TEXTCOLOR', (0, 1), (0, 1), colors.white if score < 70 else colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        return score_table
    
    def _create_severity_chart(self, severity_counts):
        """Create a bar chart showing findings by severity"""
        # Prepare data
        data = []
        labels = []
        
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        for severity in severity_order:
            count = severity_counts.get(severity, 0)
            data.append(count)
            labels.append(severity.capitalize())
        
        # Create table-based visualization
        colors_map = {
            'Critical': colors.red,
            'High': colors.orange,
            'Medium': colors.yellowgreen,
            'Low': colors.lightblue,
            'Info': colors.lightgrey
        }
        
        # Create a table showing findings by severity
        rows = []
        rows.append(['Severity', 'Count', 'Distribution'])
        
        for i, label in enumerate(labels):
            count = data[i]
            # Create a visualization bar
            bar_width = min(30, count * 3)  # Scale the bar width based on count
            bar = '█' * bar_width  # Use block character for a simple bar
            
            color = colors_map.get(label, colors.grey)
            color_hex = f'#{int(color.red * 255):02X}{int(color.green * 255):02X}{int(color.blue * 255):02X}'
            
            # Add a row for each severity
            rows.append([
                Paragraph(f"<font color='{color_hex}'><b>{label}</b></font>", 
                        ParagraphStyle('Severity', fontSize=10)),
                Paragraph(f"<b>{count}</b>", ParagraphStyle('Count', alignment=1, fontSize=10)),
                Paragraph(f"<font color='{color_hex}'>{bar}</font>", 
                        ParagraphStyle('Bar', fontName='Courier', fontSize=10))
            ])
        
        chart_table = Table(rows, colWidths=[1*inch, 0.7*inch, 3.8*inch])
        chart_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        return chart_table
    
    def _create_scan_type_chart(self, category_counts):
        """Create a chart showing findings by scan type/category"""
        # Prepare data
        categories = sorted(category_counts.keys())
        counts = [category_counts[cat] for cat in categories]
        
        # Create table-based visualization
        rows = []
        rows.append(['Scan Type', 'Findings', 'Distribution'])
        
        for i, category in enumerate(categories):
            count = counts[i]
            # Create a visualization bar
            bar_width = min(30, count * 2)  # Scale the bar width
            bar = '█' * bar_width  # Use block character for a simple bar
            
            # Add a row for each category
            rows.append([
                Paragraph(f"<b>{category.capitalize()}</b>", ParagraphStyle('Category', fontSize=10)),
                Paragraph(f"<b>{count}</b>", ParagraphStyle('Count', alignment=1, fontSize=10)),
                Paragraph(f"<font color='#3366CC'>{bar}</font>", 
                        ParagraphStyle('Bar', fontName='Courier', fontSize=10))
            ])
        
        chart_table = Table(rows, colWidths=[1.5*inch, 0.7*inch, 3.3*inch])
        chart_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        return chart_table
    
    def _get_risk_level_text(self, score):
        """Get risk level text based on security score"""
        if score >= 90:
            return "Very Secure"
        elif score >= 80:
            return "Secure"
        elif score >= 70:
            return "Moderately Secure"
        elif score >= 60:
            return "Needs Improvement"
        elif score >= 40:
            return "Insecure"
        else:
            return "Critically Insecure"
    
    def _format_duration(self, start_time, end_time):
        """Format the duration between two timestamps"""
        if not start_time or not end_time:
            return "N/A"
        
        duration = end_time - start_time
        seconds = duration.total_seconds()
        
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = int(seconds % 60)
        
        if hours > 0:
            return f"{hours} hours, {minutes} minutes, {seconds} seconds"
        else:
            return f"{minutes} minutes, {seconds} seconds"
    
    def _sanitize_html(self, html_str):
        """Sanitize HTML content to prevent parsing errors in ReportLab"""
        if not html_str or not isinstance(html_str, str):
            return ""
        
        # Replace problematic HTML tags
        sanitized = html_str.replace('<', '&lt;').replace('>', '&gt;')
        
        return sanitized
    
    def _format_json_for_pdf(self, value):
        """Safely format JSON content for PDF display"""
        try:
            if isinstance(value, (dict, list)):
                # Limit collection depth and size
                return self._limit_collection_size(value)
            return str(value)
        except Exception as e:
            return f"[Error formatting value: {str(e)}]"
    
    def _limit_collection_size(self, value, max_items=5, current_depth=0, max_depth=2):
        """Limit the size and depth of collections to prevent oversized tables"""
        if current_depth > max_depth:
            return "[Nested data]"
        
        if isinstance(value, dict):
            if len(value) > max_items:
                # Take only the first few items
                limited = {k: self._limit_collection_size(v, max_items, current_depth+1, max_depth) 
                          for k, v in list(value.items())[:max_items]}
                limited['...'] = f"[{len(value) - max_items} more items]"
                return limited
            return {k: self._limit_collection_size(v, max_items, current_depth+1, max_depth) 
                   for k, v in value.items()}
        
        elif isinstance(value, list):
            if len(value) > max_items:
                # Take only the first few items
                limited = [self._limit_collection_size(item, max_items, current_depth+1, max_depth) 
                          for item in value[:max_items]]
                limited.append(f"[{len(value) - max_items} more items]")
                return limited
            return [self._limit_collection_size(item, max_items, current_depth+1, max_depth) 
                   for item in value]
        
        return value
    
    def _get_generic_recommendations(self, category):
        """Provide generic recommendations based on scan category"""
        recommendations = {
            'headers': """
            - Implement all recommended security headers including Content-Security-Policy, 
              X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security.
            - Configure headers with secure values following industry best practices.
            - Use security header testing tools to verify your configuration.
            """,
            
            'ssl': """
            - Use TLS 1.2 or higher and disable older protocols.
            - Configure strong cipher suites and disable weak ciphers.
            - Ensure certificates are valid, not expired, and issued by trusted authorities.
            - Implement HSTS (HTTP Strict Transport Security) with a long max-age.
            """,
            
            'vulnerabilities': """
            - Keep all software, frameworks, and libraries up to date.
            - Implement proper input validation and output encoding to prevent injection attacks.
            - Use parameterized queries to prevent SQL injection.
            - Implement proper access controls and authentication mechanisms.
            - Conduct regular security testing and code reviews.
            """,
            
            'content': """
            - Remove sensitive information from HTML comments and metadata.
            - Use proper semantic HTML structure with appropriate heading levels.
            - Ensure all images have descriptive alt text for accessibility.
            - Implement proper meta tags for SEO and security.
            """,
            
            'ports': """
            - Close unnecessary ports and services.
            - Use a firewall to restrict access to essential services only.
            - Keep all network services updated and patched.
            - Consider using a Web Application Firewall (WAF) for additional protection.
            """,
            
            'csp': """
            - Implement a strict Content Security Policy that follows the principle of least privilege.
            - Avoid using 'unsafe-inline', 'unsafe-eval', and wildcard sources in your CSP.
            - Use nonces or hashes instead of 'unsafe-inline' when inline scripts are necessary.
            - Test your CSP configuration thoroughly to ensure it doesn't break functionality.
            """,
            
            'cookies': """
            - Set the Secure flag on all cookies to ensure they're only sent over HTTPS.
            - Set the HttpOnly flag on cookies that don't need to be accessed by JavaScript.
            - Implement SameSite attributes (preferably 'Strict' or 'Lax') to prevent CSRF.
            - Minimize the use of persistent cookies and use appropriate expiration times.
            """,
            
            'cors': """
            - Implement a strict CORS policy that only allows necessary origins.
            - Avoid using wildcard (*) origins especially when credentials are allowed.
            - Limit allowed methods and headers to only what is necessary.
            - Regularly review and update your CORS configuration.
            """,
            
            'server': """
            - Hide detailed server information by customizing or removing server headers.
            - Keep server software and components up to date with security patches.
            - Configure server with security best practices for your specific software.
            - Use security-focused server configurations and hardening guides.
            """
        }
        
        return recommendations.get(category, "Keep your systems updated and follow security best practices.")