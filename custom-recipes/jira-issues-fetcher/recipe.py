from dataiku.customrecipe import get_output_names_for_role
from dataiku.customrecipe import get_recipe_config
from datetime import datetime
import dataiku
import pandas as pd
from atlassian import Jira
import os
from utils.logging import logger  # Import the LazyLogger instance

config = get_recipe_config()

# Set logging level from the configuration
logging_level = config.get('logging_level', "INFO")
logger.set_level(logging_level)

logger.info("Starting the Jira issues fetcher recipe.")


def create_jira_client(api_url, username, api_token):
    """
    Creates a Jira client instance.

    Args:
        api_url (str): Jira instance URL.
        username (str): Jira username.
        api_token (str): Jira API token.

    Returns:
        Jira: Jira client instance.
    """
    return Jira(url=api_url, username=username, password=api_token)


def fetch_issues(jira_client, project_key, issue_statuses):
    """
    Fetches issues from Jira based on the given statuses and extracts relevant fields, including comments.

    Args:
        jira_client (Jira): Jira client instance.
        project_key (str): Jira project key.
        issue_statuses (list): List of issue statuses to filter by.

    Returns:
        list: A list of issues with relevant fields and comments.
    """
    logger.info("Fetching issues from Jira.")
    
    # Build the JQL query in multiple lines for better readability
    status_conditions = ", ".join([f'"{status}"' for status in issue_statuses])
    jql_query = (
        f'project = "{project_key}" '
        f'AND status IN ({status_conditions})'
    )
    
    logger.debug(f"JQL Query: {jql_query}")

    # Fetch issues using the JQL query
    issues_data = jira_client.jql(jql_query)["issues"]
    logger.info(f"Fetched {len(issues_data)} issues.")

    # Parse the issues and extract relevant fields, including comments
    parsed_issues = []
    for issue in issues_data:
        issue_key = issue["key"]
        fields = issue["fields"]
        comments_data = fields.get("comment", {}).get("comments", [])

        # Filter comments to only keep specified keys
        filtered_comments = [
            {
                "body": comment.get("body"),
                "id": comment.get("id"),
                "updated": comment.get("updated"),
                "author": comment.get("author", {}).get("displayName"),
            }
            for comment in comments_data
        ]

        # Add the parsed issue to the list
        parsed_issues.append({
            "key": issue_key,
            "summary": fields.get("summary"),
            "status": fields.get("status", {}).get("name"),
            "priority": fields.get("priority", {}).get("name"),
            "reporter": fields.get("reporter", {}).get("displayName"),
            "comments": filtered_comments,
        })

    logger.debug(f"Parsed issues: {parsed_issues}")
    return parsed_issues


def get_issues_as_dataframe(jira_client, project_key, issue_statuses):
    """
    Retrieves issues and their comments from Jira and stores them in a pandas DataFrame.

    Args:
        jira_client (Jira): Jira client instance.
        project_key (str): Jira project key.
        issue_statuses (list): List of issue statuses to filter by.

    Returns:
        pd.DataFrame: A DataFrame containing issue details and comments.
    """
    issues = fetch_issues(jira_client, project_key, issue_statuses)
    return pd.DataFrame(issues)


# Retrieve configuration parameters for Jira
jira_instance_url = config["jira_api_connection"]["jira_instance_url"]
jira_username = config["jira_api_connection"]["jira_username"]
jira_api_token = config["jira_api_connection"]["jira_api_token"]
jira_project_key = config["jira_api_connection"]["jira_project_key"]
issue_statuses = config["issue_statuses"]

# Create Jira client
jira_client = create_jira_client(jira_instance_url, jira_username, jira_api_token)

logger.info("Starting issue retrieval process.")
df_issues = get_issues_as_dataframe(jira_client, jira_project_key, issue_statuses)

# Get the output dataset
output_name = get_output_names_for_role('data_output')[0]
output_dataset = dataiku.Dataset(output_name)

logger.info(f"Writing issues to output dataset: {output_name}")
# Write to the output dataset
output_dataset.write_with_schema(df_issues)
logger.info("Issues successfully written to the output dataset.")