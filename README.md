# Description
`nightvision azure importer` is a script used to automate the process of importing security vulnerability findings from a nightvision scan results file into Azure DevOps as work items.

# Usage Example

To run the nightvision_azure_importer.py script, you will need to specify the Azure DevOps organization, project, personal access token (PAT), and the path to the SARIF file containing the security findings. Here’s how you can execute the script from the command line:

  ```

    python3 nightvision_azure_importer.py --organization "your_organization" --project "your_project" --patoken "your_personal_access_token" --sarif results.sarif

  ```
