# Website Profiling Tool

A comprehensive tool for gathering detailed information about websites, including IP, hosting, SSL, DNS, and more. This tool is designed to be both informative and visually appealing, leveraging the `rich` library for output formatting.

## Features

- **Banner Display**: Displays a stylized banner at the beginning of the execution.
- **Website Info**: Retrieves server headers, load time, and content analysis.
- **Security Headers**: Extracts and displays important security headers.
- **IP and Hosting Info**: Fetches IP address and hosting details using IPWhois.
- **SSL Info**: Retrieves SSL certificate information including issuer, subject, and validity.
- **DNS Info**: Displays the A records (IP addresses) for the domain.
- **Technology Stack**: Identifies the server and other technologies used by the website.
- **Subdomains**: Detects and lists subdomains related to the website.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/website-profiling-tool.git
   cd website-profiling-tool
   ```

2. **Install Dependencies**

   Ensure you have Python installed, then run:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the script and follow the prompts:

```bash
python website_profiling_tool.py
```

You will be prompted to enter the website URL. The tool will then display a series of panels with information about the website.

## Example Output

![image](https://github.com/user-attachments/assets/6fd43b2b-8e58-4797-bbb0-53c8241a66ad)

## Requirements

- Python 3.x
- Required Python packages are listed in `requirements.txt`:
  - `socket`
  - `ssl`
  - `dns.resolver`
  - `requests`
  - `OpenSSL`
  - `re`
  - `ipwhois`
  - `rich`
  - `pyfiglet`
  - `urllib.parse`
  - `bs4`
  - `time`
  - `collections`

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
