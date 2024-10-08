# SQL Injection Scanner

## Overview

**SQL Injection Scanner** is a Python program designed to detect SQL injection vulnerabilities in web applications. SQL injection is a common security vulnerability that occurs when an attacker inserts malicious SQL code into input fields, potentially manipulating the database or executing unauthorized queries. This program aims to identify potential SQL injection vulnerabilities in web forms by testing various payloads and analyzing the server's response.

## Background

### SQL (Structured Query Language)

SQL is a domain-specific language used in programming and managing relational databases. It allows users to perform tasks such as querying data, inserting, updating, and deleting records. SQL is widely used in web development for interacting with backend databases.

### SQL Vulnerabilities

SQL injection is one of the most common and dangerous vulnerabilities in web applications. It occurs when untrusted data is inserted into SQL queries without proper validation or sanitization. Attackers exploit this vulnerability by injecting malicious SQL code into input fields, potentially gaining unauthorized access to sensitive data, manipulating database contents, or executing arbitrary commands on the server.

### CIA Triad

The CIA Triad, consisting of **Confidentiality**, **Integrity**, and **Availability**, is a fundamental concept in cybersecurity. SQL injection vulnerabilities can compromise all three aspects of the CIA Triad:

- **Confidentiality**: Attackers can extract confidential information from databases, such as user credentials, financial data, or personal records.
- **Integrity**: Injection attacks can modify or delete database records, leading to data corruption or unauthorized changes.
- **Availability**: SQL injection attacks can disrupt the availability of web applications by causing server crashes, denial-of-service (DoS) attacks, or other forms of disruption.

## Operation

### SQL Injection Scanner Diagram
/home/bot/Pictures/Screenshots/Screenshot from 2024-10-06 14-35-37.png

### Description

1. **Initialization**: The program starts by importing necessary libraries and defining a custom User-Agent header for HTTP requests.

2. **Form Extraction**: It retrieves HTML forms from a specified URL using BeautifulSoup. These forms contain input fields that are potential targets for SQL injection.

3. **Form Analysis**: For each form, the program extracts details such as action URL, method (GET or POST), and input fields.

4. **Payload Injection**: It generates modified payloads by appending single and double quotes to input values. These payloads are used to test for SQL injection vulnerabilities.

5. **Request Sending**: The program sends HTTP requests to the server, injecting the modified payloads into form submissions.

6. **Response Analysis**: It analyzes the server's response to detect common SQL error messages indicating potential vulnerabilities.

7. **Vulnerability Detection**: If a vulnerability is detected, the program notifies the user and logs the result for further analysis. Otherwise, it concludes that no vulnerability is found.

### Mathematical Elaboration

The SQL injection scanner utilizes various mathematical concepts and techniques to analyze the server's response and detect potential vulnerabilities:

- **Set Theory**: The program uses sets to define a collection of common SQL error messages that indicate possible SQL injection vulnerabilities.
  
- **Boolean Logic**: It employs Boolean logic to check if any of the error messages are present in the server's response, determining whether a vulnerability exists.

- **Probability Theory**: While not explicitly implemented, the program's detection mechanism can be analyzed probabilistically to estimate the likelihood of a successful SQL injection attack.

## Dependencies

- Python 3
- Requests library
- BeautifulSoup library
- Other dependencies listed in `requirements.txt`

## Installation

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/FlxBot001/sqlInjection_Scanner.git
   ```

2. Navigate to the project directory:

   ```bash
   cd sqlInjection_Scanner
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the SQL Injection Scanner script with the desired URL to scan for vulnerabilities:

```bash
python sql_injection_scanner.py https://example.com
```

## Recommendations

- **Use Responsibly**: This program is intended for educational purposes only. It should not be used for malicious intent or unauthorized testing of web applications without proper permission.
  
- **Environment Setup**: It's advisable to use a virtual environment (e.g., `venv` or `conda`) for installing dependencies to avoid conflicts with other projects.

- **Error Handling**: Improve error handling in the code to gracefully manage potential exceptions during requests or form analysis.

- **Logging**: Utilize logging effectively to maintain records of scans, which can aid in identifying patterns of vulnerabilities over time.

- **Regular Updates**: Regularly update the dependency packages to mitigate any vulnerabilities in the libraries used.

## Disclaimer

This program is provided for educational purposes only. It should not be used for malicious intent or unauthorized testing of web applications without proper permission.

---

For additional information, visit the project's [GitHub page](https://github.com/FlxBot001/sqlInjection_Scanner.
```
