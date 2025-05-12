# Jira Agent Tool

This plugin provides integration with Jira as an agent tool, using the Jira Python API. It allows you to create, retrieve, update, and manage Jira issues programmatically.

## Features

- Create new Jira issues
- Retrieve issues by key
- Close issues
- Update issue priorities
- Get issues by reporter
- User lookup by email or account ID
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

Request:
```json
{
    "action": "create_issue",
    "reporter": "user@example.com",
    "issuetype": "Bug",
    "summary": "Issue summary",
    "description": "Detailed description",
    "priority": "Medium"
}
```

Success Response:
```json
{
    "output": {
        "status": "ok",
        "message": "Issue created successfully",
        "issue_key": "PROJECT-123",
        "url": "https://your-instance.atlassian.net/browse/PROJECT-123",
        "reporter_display_name": "John Doe",
        "summary": "Issue summary",
        "status": "Open",
        "priority": "Medium",
        "issue_type": "Bug",
        "created": "2024-03-20T10:00:00.000+0000"
    }
}
```

### Getting an Issue

Request:
```json
{
    "action": "get_issue_by_key",
    "issue_key": "PROJECT-123",
    "reporter": "user@example.com"
}
```

Success Response:
```json
{
    "output": {
        "status": "ok",
        "message": "Issue retrieved successfully",
        "issue_key": "PROJECT-123",
        "url": "https://your-instance.atlassian.net/browse/PROJECT-123",
        "reporter_display_name": "John Doe",
        "summary": "Issue summary",
        "status": "Open",
        "priority": "Medium",
        "issue_type": "Bug",
        "created": "2024-03-20T10:00:00.000+0000"
    }
}
```

### Closing an Issue

Request:
```json
{
    "action": "close_issue",
    "issue_key": "PROJECT-123",
    "reporter": "user@example.com"
}
```

Success Response:
```json
{
    "output": {
        "status": "ok",
        "message": "Issue closed successfully",
        "issue_key": "PROJECT-123",
        "url": "https://your-instance.atlassian.net/browse/PROJECT-123"
    }
}
```

### Updating Issue Priority

Request:
```json
{
    "action": "update_issue_priority",
    "issue_key": "PROJECT-123",
    "reporter": "user@example.com",
    "priority": "High"
}
```

Success Response:
```json
{
    "output": {
        "status": "ok",
        "message": "Issue priority updated successfully",
        "issue_key": "PROJECT-123",
        "url": "https://your-instance.atlassian.net/browse/PROJECT-123",
        "priority": "High"
    }
}
```

### Getting Issues by Reporter

Request:
```json
{
    "action": "get_issues_by_reporter",
    "reporter": "user@example.com"
}
```

Success Response:
```json
{
    "output": {
        "status": "ok",
        "message": "Found 2 issues for reporter user@example.com",
        "reporter_display_name": "John Doe",
        "issues": [
            {
                "issue_key": "PROJECT-123",
                "url": "https://your-instance.atlassian.net/browse/PROJECT-123",
                "summary": "Issue summary 1",
                "status": "Open",
                "priority": "Medium",
                "issue_type": "Bug",
                "created": "2024-03-20T10:00:00.000+0000"
            },
            {
                "issue_key": "PROJECT-124",
                "url": "https://your-instance.atlassian.net/browse/PROJECT-124",
                "summary": "Issue summary 2",
                "status": "Closed",
                "priority": "High",
                "issue_type": "Task",
                "created": "2024-03-19T15:30:00.000+0000"
            }
        ]
    }
}
```

### User Lookup Operations

#### Find User Account ID
Request:
```json
{
    "action": "find_user_account_id",
    "email": "user@example.com"
}
```

Success Response:
```json
{
    "output": {
        "status": "ok",
        "message": "Found accountId for user with email user@example.com: 123456:7890abcd-efgh-ijkl-mnop-qrstuvwxyz",
        "account_id": "123456:7890abcd-efgh-ijkl-mnop-qrstuvwxyz",
        "email": "user@example.com"
    }
}
```

#### Find User Display Name by Account ID
Request:
```json
{
    "action": "find_user_display_name_by_account_id",
    "account_id": "123456:7890abcd-efgh-ijkl-mnop-qrstuvwxyz"
}
```

Success Response:
```json
{
    "output": {
        "status": "ok",
        "message": "Found display name for accountId 123456:7890abcd-efgh-ijkl-mnop-qrstuvwxyz: John Doe",
        "account_id": "123456:7890abcd-efgh-ijkl-mnop-qrstuvwxyz",
        "display_name": "John Doe"
    }
}
```

#### Find User Display Name by Email
Request:
```json
{
    "action": "find_user_display_name_by_email",
    "email": "user@example.com"
}
```

Success Response:
```json
{
    "output": {
        "status": "ok",
        "message": "Found display name for email user@example.com: John Doe",
        "email": "user@example.com",
        "account_id": "123456:7890abcd-efgh-ijkl-mnop-qrstuvwxyz",
        "display_name": "John Doe"
    }
}
```

## Error Handling

The tool includes comprehensive error handling and logging:

### Standardized Response Format
All responses follow a consistent format:
```json
{
    "output": {
        "status": "ok" | "ko",
        "message": "Human readable message",
        // Operation-specific data
    }
}
```

### Common Error Scenarios
- Invalid configuration
- Missing required fields
- Invalid issue type or priority
- Reporter verification failure
- API authentication errors
- Network connectivity issues

### Logging
- DEBUG: Detailed operation information
- INFO: Operation results and important events
- WARNING: Non-critical issues
- ERROR: Critical failures and exceptions

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
