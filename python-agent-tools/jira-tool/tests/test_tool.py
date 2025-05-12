import unittest
from unittest.mock import MagicMock, patch
from tool import JiraTool

class TestJiraTool(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.config = {
            "jira_api_connection": {
                "jira_instance_url": "https://test.atlassian.net",
                "jira_username": "test@example.com",
                "jira_api_token": "test-token",
                "jira_project_key": "TEST",
                "jira_cloud": True,
                "issue_types": ["Bug", "Task", "Story"]
            },
            "logging_level": "DEBUG"
        }
        self.tool = JiraTool()
        self.tool.set_config(self.config, {})

    def test_validate_config(self):
        """Test configuration validation."""
        # Test valid config
        self.tool._validate_config(self.config)

        # Test missing required field
        invalid_config = self.config.copy()
        del invalid_config["jira_api_connection"]["jira_instance_url"]
        with self.assertRaises(ValueError):
            self.tool._validate_config(invalid_config)

        # Test invalid URL
        invalid_config = self.config.copy()
        invalid_config["jira_api_connection"]["jira_instance_url"] = "invalid-url"
        with self.assertRaises(ValueError):
            self.tool._validate_config(invalid_config)

        # Test invalid issue types
        invalid_config = self.config.copy()
        invalid_config["jira_api_connection"]["issue_types"] = []
        with self.assertRaises(ValueError):
            self.tool._validate_config(invalid_config)

        # Test invalid jira_cloud type
        invalid_config = self.config.copy()
        invalid_config["jira_api_connection"]["jira_cloud"] = "true"
        with self.assertRaises(ValueError):
            self.tool._validate_config(invalid_config)

    def test_find_user_account_id(self):
        """Test finding user account ID by email."""
        mock_user = {"accountId": "test-account-id"}
        self.tool.jira.user_find_by_user_string = MagicMock(return_value=[mock_user])

        # Test successful lookup
        result = self.tool.find_user_account_id({"email": "test@example.com"})
        self.assertEqual(result["output"]["action_status"], "ok")
        self.assertEqual(result["output"]["account_id"], "test-account-id")

        # Test user not found
        self.tool.jira.user_find_by_user_string = MagicMock(return_value=[])
        result = self.tool.find_user_account_id({"email": "nonexistent@example.com"})
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test API error
        self.tool.jira.user_find_by_user_string = MagicMock(side_effect=Exception("API Error"))
        result = self.tool.find_user_account_id({"email": "test@example.com"})
        self.assertEqual(result["output"]["action_status"], "ko")
        self.assertIn("error_details", result["output"])

        # Test missing email
        result = self.tool.find_user_account_id({})
        self.assertEqual(result["output"]["action_status"], "ko")

    def test_find_user_display_name_by_account_id(self):
        """Test finding user display name by account ID."""
        mock_user = {"displayName": "Test User"}
        self.tool.jira.user_find_by_user_string = MagicMock(return_value=[mock_user])

        # Test successful lookup
        result = self.tool.find_user_display_name_by_account_id({"account_id": "test-account-id"})
        self.assertEqual(result["output"]["action_status"], "ok")
        self.assertEqual(result["output"]["display_name"], "Test User")

        # Test invalid account ID (email)
        result = self.tool.find_user_display_name_by_account_id({"account_id": "test@example.com"})
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test user not found
        self.tool.jira.user_find_by_user_string = MagicMock(return_value=[])
        result = self.tool.find_user_display_name_by_account_id({"account_id": "nonexistent-id"})
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test API error
        self.tool.jira.user_find_by_user_string = MagicMock(side_effect=Exception("API Error"))
        result = self.tool.find_user_display_name_by_account_id({"account_id": "test-account-id"})
        self.assertEqual(result["output"]["action_status"], "ko")
        self.assertIn("error_details", result["output"])

        # Test missing account_id
        result = self.tool.find_user_display_name_by_account_id({})
        self.assertEqual(result["output"]["action_status"], "ko")

    def test_find_user_display_name_by_email(self):
        """Test finding user display name by email."""
        # Test successful lookup
        self.tool.find_user_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "account_id": "test-account-id"}
        })
        self.tool.find_user_display_name_by_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "display_name": "Test User"}
        })

        result = self.tool.find_user_display_name_by_email({"email": "test@example.com"})
        self.assertEqual(result["output"]["action_status"], "ok")
        self.assertEqual(result["output"]["display_name"], "Test User")

        # Test account ID lookup failure
        self.tool.find_user_account_id = MagicMock(return_value={
            "output": {"action_status": "ko", "message": "User not found"}
        })
        result = self.tool.find_user_display_name_by_email({"email": "nonexistent@example.com"})
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test display name lookup failure
        self.tool.find_user_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "account_id": "test-account-id"}
        })
        self.tool.find_user_display_name_by_account_id = MagicMock(return_value={
            "output": {"action_status": "ko", "message": "Display name not found"}
        })
        result = self.tool.find_user_display_name_by_email({"email": "test@example.com"})
        self.assertEqual(result["output"]["action_status"], "ko")

    def test_create_issue(self):
        """Test creating a new issue."""
        mock_issue = {
            "key": "TEST-123",
            "fields": {
                "summary": "Test Issue",
                "status": {"name": "Open"},
                "priority": {"name": "Medium"},
                "issuetype": {"name": "Bug"},
                "created": "2024-03-20T10:00:00.000+0000"
            }
        }
        self.tool.jira.create_issue = MagicMock(return_value=mock_issue)
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        self.tool.find_user_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "account_id": "test-account-id"}
        })
        self.tool.find_user_display_name_by_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "display_name": "Test User"}
        })

        # Test successful creation
        result = self.tool.create_issue({
            "reporter": "test@example.com",
            "issuetype": "Bug",
            "summary": "Test Issue",
            "description": "Test Description",
            "priority": "Medium"
        })
        self.assertEqual(result["output"]["action_status"], "ok")
        self.assertEqual(result["output"]["issue_key"], "TEST-123")

        # Test invalid issue type
        result = self.tool.create_issue({
            "reporter": "test@example.com",
            "issuetype": "InvalidType",
            "summary": "Test Issue",
            "description": "Test Description"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test invalid priority
        result = self.tool.create_issue({
            "reporter": "test@example.com",
            "issuetype": "Bug",
            "summary": "Test Issue",
            "description": "Test Description",
            "priority": "InvalidPriority"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test API error
        self.tool.jira.create_issue = MagicMock(side_effect=Exception("API Error"))
        result = self.tool.create_issue({
            "reporter": "test@example.com",
            "issuetype": "Bug",
            "summary": "Test Issue",
            "description": "Test Description"
        })
        self.assertEqual(result["output"]["action_status"], "ko")
        self.assertIn("error_details", result["output"])

    def test_get_issue_by_key(self):
        """Test getting an issue by key."""
        mock_issue = {
            "key": "TEST-123",
            "fields": {
                "reporter": {"accountId": "test-account-id"},
                "summary": "Test Issue",
                "status": {"name": "Open"},
                "priority": {"name": "Medium"},
                "issuetype": {"name": "Bug"},
                "created": "2024-03-20T10:00:00.000+0000"
            }
        }
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        self.tool.find_user_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "account_id": "test-account-id"}
        })
        self.tool.find_user_display_name_by_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "display_name": "Test User"}
        })

        # Test successful retrieval
        result = self.tool.get_issue_by_key({
            "issue_key": "TEST-123",
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ok")
        self.assertEqual(result["output"]["issue_key"], "TEST-123")

        # Test issue not found
        self.tool.jira.issue = MagicMock(side_effect=Exception("Issue not found"))
        result = self.tool.get_issue_by_key({
            "issue_key": "TEST-999",
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test reporter verification failure
        mock_issue["fields"]["reporter"]["accountId"] = "different-account-id"
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        result = self.tool.get_issue_by_key({
            "issue_key": "TEST-123",
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

    def test_close_issue(self):
        """Test closing an issue."""
        mock_issue = {
            "key": "TEST-123",
            "fields": {
                "reporter": {"accountId": "test-account-id"},
                "summary": "Test Issue",
                "status": {"name": "Closed"},
                "priority": {"name": "Medium"},
                "issuetype": {"name": "Bug"},
                "created": "2024-03-20T10:00:00.000+0000"
            }
        }
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        self.tool.jira.set_issue_status = MagicMock(return_value=mock_issue)
        self.tool.jira.issue_add_comment = MagicMock()
        self.tool.find_user_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "account_id": "test-account-id"}
        })
        self.tool.find_user_display_name_by_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "display_name": "Test User"}
        })

        # Test successful closure
        result = self.tool.close_issue({
            "issue_key": "TEST-123",
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ok")
        self.assertEqual(result["output"]["issue_key"], "TEST-123")

        # Test issue not found
        self.tool.jira.issue = MagicMock(side_effect=Exception("Issue not found"))
        result = self.tool.close_issue({
            "issue_key": "TEST-999",
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test reporter verification failure
        mock_issue["fields"]["reporter"]["accountId"] = "different-account-id"
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        result = self.tool.close_issue({
            "issue_key": "TEST-123",
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test status update failure
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        self.tool.jira.set_issue_status = MagicMock(side_effect=Exception("Status update failed"))
        result = self.tool.close_issue({
            "issue_key": "TEST-123",
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

    def test_update_issue_priority(self):
        """Test updating issue priority."""
        mock_issue = {
            "key": "TEST-123",
            "fields": {
                "reporter": {"accountId": "test-account-id"},
                "summary": "Test Issue",
                "status": {"name": "Open"},
                "priority": {"name": "High"},
                "issuetype": {"name": "Bug"},
                "created": "2024-03-20T10:00:00.000+0000"
            }
        }
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        self.tool.jira.issue_update = MagicMock(return_value=mock_issue)
        self.tool.jira.issue_add_comment = MagicMock()
        self.tool.find_user_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "account_id": "test-account-id"}
        })
        self.tool.find_user_display_name_by_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "display_name": "Test User"}
        })

        # Test successful update
        result = self.tool.update_issue_priority({
            "issue_key": "TEST-123",
            "reporter": "test@example.com",
            "priority": "High"
        })
        self.assertEqual(result["output"]["action_status"], "ok")
        self.assertEqual(result["output"]["issue_key"], "TEST-123")
        self.assertEqual(result["output"]["priority"], "High")

        # Test invalid priority
        result = self.tool.update_issue_priority({
            "issue_key": "TEST-123",
            "reporter": "test@example.com",
            "priority": "InvalidPriority"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test issue not found
        self.tool.jira.issue = MagicMock(side_effect=Exception("Issue not found"))
        result = self.tool.update_issue_priority({
            "issue_key": "TEST-999",
            "reporter": "test@example.com",
            "priority": "High"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test reporter verification failure
        mock_issue["fields"]["reporter"]["accountId"] = "different-account-id"
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        result = self.tool.update_issue_priority({
            "issue_key": "TEST-123",
            "reporter": "test@example.com",
            "priority": "High"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test priority update failure
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        self.tool.jira.issue_update = MagicMock(side_effect=Exception("Priority update failed"))
        result = self.tool.update_issue_priority({
            "issue_key": "TEST-123",
            "reporter": "test@example.com",
            "priority": "High"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test same priority
        mock_issue["fields"]["priority"]["name"] = "High"
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        result = self.tool.update_issue_priority({
            "issue_key": "TEST-123",
            "reporter": "test@example.com",
            "priority": "High"
        })
        self.assertEqual(result["output"]["action_status"], "ok")
        self.assertIn("already set", result["output"]["message"])

    def test_get_issues_by_reporter(self):
        """Test getting issues by reporter."""
        mock_issues = {
            "issues": [{
                "key": "TEST-123",
                "fields": {
                    "summary": "Test Issue",
                    "status": {"name": "Open"},
                    "priority": {"name": "Medium"},
                    "issuetype": {"name": "Bug"},
                    "created": "2024-03-20T10:00:00.000+0000"
                }
            }]
        }
        self.tool.jira.jql = MagicMock(return_value=mock_issues)
        self.tool.find_user_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "account_id": "test-account-id"}
        })
        self.tool.find_user_display_name_by_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "display_name": "Test User"}
        })

        # Test successful retrieval
        result = self.tool.get_issues_by_reporter({
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ok")
        self.assertEqual(len(result["output"]["issues"]), 1)
        self.assertEqual(result["output"]["issues"][0]["issue_key"], "TEST-123")

        # Test no issues found
        self.tool.jira.jql = MagicMock(return_value={"issues": []})
        result = self.tool.get_issues_by_reporter({
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ok")
        self.assertEqual(len(result["output"]["issues"]), 0)

        # Test API error
        self.tool.jira.jql = MagicMock(side_effect=Exception("API Error"))
        result = self.tool.get_issues_by_reporter({
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ko")
        self.assertIn("error_details", result["output"])

    def test_error_handling(self):
        """Test error handling in various scenarios."""
        # Test missing required fields
        result = self.tool.create_issue({})
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test invalid priority
        result = self.tool.update_issue_priority({
            "issue_key": "TEST-123",
            "reporter": "test@example.com",
            "priority": "Invalid"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test reporter verification failure
        mock_issue = {
            "fields": {
                "reporter": {"accountId": "different-account-id"}
            }
        }
        self.tool.jira.issue = MagicMock(return_value=mock_issue)
        self.tool.find_user_account_id = MagicMock(return_value={
            "output": {"action_status": "ok", "account_id": "test-account-id"}
        })

        result = self.tool.get_issue_by_key({
            "issue_key": "TEST-123",
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ko")

        # Test API error with traceback
        self.tool.jira.issue = MagicMock(side_effect=Exception("API Error"))
        result = self.tool.get_issue_by_key({
            "issue_key": "TEST-123",
            "reporter": "test@example.com"
        })
        self.assertEqual(result["output"]["action_status"], "ko")
        self.assertIn("error_details", result["output"])
        self.assertIn("location", result["output"]["error_details"])
        self.assertIn("context", result["output"]["error_details"])
        self.assertIn("line", result["output"]["error_details"])
        self.assertIn("error", result["output"]["error_details"])

if __name__ == '__main__':
    unittest.main() 