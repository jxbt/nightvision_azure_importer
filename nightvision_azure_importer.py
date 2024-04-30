import json
import requests
from base64 import b64encode
import markdown
from bs4 import BeautifulSoup
import sys
import getopt
import re

# Azure DevOps details
organization = ''
project = ''
pat = ''

# path of the SARIF file to parse
sarif_file_path = ''

opts, args = getopt.getopt(sys.argv[1:],longopts=["patoken=","organization=","project=","sarif="],shortopts="t:o:p:s:")

for opt,arg in opts:

    if opt == "--patoken" or opt == "-t":
        pat = str(arg)
    elif opt == "--organization" or opt == "-o":
        organization = str(arg)
    elif opt == "--project" or opt == "-p":
        project = str(arg)
    elif opt == "--sarif" or opt == "-s":
        sarif_file_path = str(arg) 
    else:
        pass


# Azure DevOps API endpoint for creating work items
api_url = f"https://dev.azure.com/{organization}/{project}/_apis/wit/workitems/$Issue?api-version=6.0"

# Headers for Azure DevOps API
credentials = b64encode(bytes(f":{pat}", 'utf-8')).decode('ascii')
headers = {
    'Authorization': f'Basic {credentials}',
    'Content-Type': 'application/json-patch+json'
}

def create_work_item(rule_id,issue_title, issue_description):
    """Create a single work item in Azure DevOps with URLs converted to HTML links."""
    # Convert Markdown to HTML
    html_description = markdown.markdown(issue_description)
    
    # Convert URLs into clickable links
    url_pattern = re.compile(
        r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    )
    html_description = url_pattern.sub(
        lambda x: f'<a href="{x.group(0)}">{x.group(0)}</a>', html_description
    )
    
    soup = BeautifulSoup(html_description, 'html.parser')
    formatted_description = soup.prettify()

    json_data = [
        {"op": "add", "path": "/fields/System.Title", "value": issue_title},
        {"op": "add", "path": "/fields/System.Description", "value": formatted_description},
        {"op": "add", "path": "/fields/System.Tags", "value": "Security Vulnerability"}
    ]
    response = requests.post(api_url, headers=headers, json=json_data)
    print(f"Work item created successfully - {rule_id}." if response.status_code == 200 else f"Failed to create work item: {response.text} - {rule_id}")

def parse_sarif_and_create_work_items():
    """Parse SARIF file and create work items for each finding."""
    with open(sarif_file_path, 'r') as file:
        sarif_data = json.load(file)
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            title = result['message']['text']
            rule_id = result['ruleId']
            description = next((rule['fullDescription']['text'] for rule in run['tool']['driver']['rules'] if rule['id'] == rule_id), "No description available.")
           
            create_work_item(rule_id,title, description)

if __name__ == "__main__":
    parse_sarif_and_create_work_items()
