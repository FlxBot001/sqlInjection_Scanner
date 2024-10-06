import os
from fpdf import FPDF
from datetime import datetime
import platform

class PDFReport:
    def __init__(self, filename):
        self.filename = filename
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        self.pdf.add_page()
        self.pdf.set_font("Arial", size=12)

    def add_header(self, title):
        self.pdf.set_font("Arial", 'B', 16)
        self.pdf.cell(0, 10, title, ln=True, align='C')
        self.pdf.set_font("Arial", size=12)
        self.pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        self.pdf.cell(0, 10, f"Time Zone: {datetime.now().astimezone().tzinfo}", ln=True, align='C')
        self.pdf.cell(0, 10, f"Scanned Machine: {platform.node()}", ln=True, align='C')
        self.pdf.cell(0, 10, f"Application: SQL Injection Vulnerability Scanner", ln=True, align='C')
        self.pdf.cell(0, 10, f"Website: {self.filename}", ln=True, align='C')
        self.pdf.cell(0, 10, f"Hosting Platform: {platform.system()}", ln=True, align='C')
        self.pdf.cell(0, 10, '', ln=True)  # Empty line

    def add_vulnerability(self, form, vulnerabilities):
        self.pdf.set_font("Arial", 'B', 14)
        self.pdf.cell(0, 10, f"Affected Form: {form}", ln=True)
        self.pdf.set_font("Arial", size=12)
        for vulnerability in vulnerabilities:
            self.pdf.cell(0, 10, f" - {vulnerability}", ln=True)
        self.pdf.cell(0, 10, '', ln=True)  # Empty line

    def add_summary(self, total_vulnerabilities):
        self.pdf.set_font("Arial", 'B', 14)
        self.pdf.cell(0, 10, "Summary", ln=True)
        self.pdf.set_font("Arial", size=12)
        self.pdf.cell(0, 10, f"Total Vulnerabilities Found: {total_vulnerabilities}", ln=True)

    def save(self):
        self.pdf.output(self.filename)

def generate_report(filename, vulnerabilities_summary):
    report = PDFReport(filename)
    report.add_header("SQL Injection Vulnerability Report")
    
    total_vulnerabilities = 0
    for form, vulnerabilities in vulnerabilities_summary.items():
        report.add_vulnerability(form, vulnerabilities)
        total_vulnerabilities += len(vulnerabilities)

    report.add_summary(total_vulnerabilities)
    report.save()

