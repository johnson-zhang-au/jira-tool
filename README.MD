# Jira Agent Tool

This plugin provides integration with Jira as an agent tool, using the Jira Python API. It allows you to create, retrieve, update, and manage Jira issues programmatically.

## Features

- Create new Jira issues
- Retrieve issues by key
- Close issues
- Update issue priorities
- Get issues by reporter
- Fetch issues with comments and detailed information
- Support for both Jira Cloud and Jira Server instances

## Installation

1. Clone this repository:
```bash
git clone https://github.com/your-username/jira-tool.git
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

The tool requires the following configuration parameters:

```json
{
    "jira_api_connection": {
        "jira_instance_url": "https://your-instance.atlassian.net",
        "jira_username": "your-email@example.com",
        "jira_api_token": "your-api-token",
        "jira_project_key": "PROJECT",
        "jira_cloud": true,
        "issue_types": ["Bug", "Task", "Story"]
    },
    "logging_level": "INFO"
}
```

### Configuration Parameters

- `jira_instance_url`: Your Jira instance URL
- `jira_username`: Your Jira account email
- `jira_api_token`: Your Jira API token (generate from Atlassian account settings)
- `jira_project_key`: The key of your Jira project
- `jira_cloud`: Set to `true` for Jira Cloud, `false` for Jira Server
- `issue_types`: List of available issue types in your project
- `logging_level`: Logging level (DEBUG, INFO, WARNING, ERROR)

## Usage

### Creating an Issue

```python
{
    "action": "create_issue",
    "reporter": "user@example.com",
    "issuetype": "Bug",
    "summary": "Issue summary",
    "description": "Detailed description",
    "priority": "Medium"
}
```

### Getting an Issue

```python
{
    "action": "get_issue_by_key",
    "issue_key": "PROJECT-123",
    "reporter": "user@example.com"
}
```

### Closing an Issue

```python
{
    "action": "close_issue",
    "issue_key": "PROJECT-123",
    "reporter": "user@example.com"
}
```

### Updating Issue Priority

```python
{
    "action": "update_issue_priority",
    "issue_key": "PROJECT-123",
    "priority": "High",
    "reporter": "user@example.com"
}
```

### Getting Issues by Reporter

```python
{
    "action": "get_issues_by_reporter",
    "reporter": "user@example.com"
}
```

## Custom Recipe: Jira Issues Fetcher

The plugin includes a custom recipe that allows you to fetch issues from Jira and store them in a Dataiku dataset. The recipe supports:

- Filtering issues by status
- Extracting issue details including comments
- Storing results in a structured format

### Recipe Configuration

```json
{
    "jira_api_connection": {
        "jira_instance_url": "https://your-instance.atlassian.net",
        "jira_username": "your-email@example.com",
        "jira_api_token": "your-api-token",
        "jira_project_key": "PROJECT"
    },
    "issue_statuses": ["Open", "In Progress", "Done"]
}
```

## Error Handling

The tool includes comprehensive error handling and logging:
- Input validation for all operations
- Reporter verification for sensitive operations
- Detailed error messages and logging
- Support for different logging levels

## Disclaimer

This plugin is developed and maintained by Dataiku community members and is not an official Dataiku plugin.  
Contributors work on this project in their personal time and will do their best to fix issues or add new features, but support or updates are not guaranteed.

This plugin is provided "as is" without warranty of any kind, express or implied.  
Use at your own risk. The authors are not responsible for any damage or loss caused by the use of this software.  
All trademarks and copyrights belong to their respective owners.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
