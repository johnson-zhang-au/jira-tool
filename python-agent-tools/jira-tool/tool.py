from dataiku.llm.agent_tools import BaseAgentTool
from atlassian import Jira
from utils.logging import logger  # Import the LazyLogger class

class JiraTool(BaseAgentTool):
    def set_config(self, config, plugin_config):
        self.config = config
        self.jira_instance_url = self.config["jira_api_connection"]["jira_instance_url"]
        self.jira_username = self.config["jira_api_connection"]["jira_username"]
        self.jira_api_token = self.config["jira_api_connection"]["jira_api_token"]
        self.jira_project_key = self.config["jira_api_connection"]["jira_project_key"]
        self.jira_cloud = self.config["jira_api_connection"]["jira_cloud"]
        self.issue_types = self.config["jira_api_connection"]["issue_types"]

        logger.debug("Initializing Jira client with the provided configuration.")
        # Set up the Jira client
        self.jira = Jira(
            url=self.jira_instance_url,
            username=self.jira_username,
            password=self.jira_api_token,
            cloud=self.jira_cloud
        )
        logger.debug("Jira client initialized successfully.")

        # Set up logging
        self.setup_logging()

    def setup_logging(self):
        """
        Sets up the logging level using the LazyLogger class.
        """
        # Get the logging level from the configuration, default to INFO
        logging_level = self.config.get("logging_level", "INFO")

        try:
            # Set the logging level dynamically
            logger.set_level(logging_level)
            logger.info(f"Logging initialized with level: {logging_level}")
        except ValueError as e:
            # Handle invalid logging levels
            logger.error(f"Invalid logging level '{logging_level}': {str(e)}")
            raise

    def get_descriptor(self, tool):
        logger.debug("Generating descriptor for the Jira tool.")
        return {
            "description": "Interacts with Jira to create, retrieve, close, and update issues",
            "inputSchema": {
                "$id": "https://dataiku.com/agents/tools/jira/input",
                "title": "Input for the Jira tool",
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["create_issue", "get_issue_by_key", "close_issue", "update_issue_priority", "get_issues_by_reporter"],
                        "description": "The action to perform (create_issue, get_issue_by_key, close_issue, update_issue_priority, or get_issues_by_reporter)"
                    },
                    "issue_key": {
                        "type": "string",
                        "description": "Issue key (required for get_issue_by_key, close_issue, or update_issue_priority)"
                    },
                    "reporter": {
                        "type": "string",
                        "description": "Reporter's username or email (required for create_issue, get_issue_by_key, close_issue, or update_issue_priority)"
                    },
                    "summary": {
                        "type": "string",
                        "description": "Issue summary (required for create_issue action)"
                    },
                    "description": {
                        "type": "string",
                        "description": "Issue description (required for create_issue action)"
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["Lowest", "Low", "Medium", "High", "Highest"],
                        "default": "Medium",
                        "description": "Issue priority (required for create_issue or update_issue_priority action)"
                    },
                    "issuetype": {
                        "type": "string",
                        "enum": self.issue_types,
                        "description": f"Issue type (must be one of: {', '.join(self.issue_types)}) (required for create_issue action)"
                    }
                },
                "required": ["action"]
            }
        }

    def invoke(self, input, trace):
        args = input["input"]
        action = args["action"]

        logger.info(f"Invoking action: {action}")
        logger.debug(f"Input arguments: {args}")
        
        # Log inputs and config to trace
        trace.span["name"] = "JIRA_TOOL_CALL"
        for key, value in args.items():
            trace.inputs[key] = value
        trace.attributes["config"] = self.config

        if action == "create_issue":
            result = self.create_issue(args)
            # Log outputs to trace
            trace.outputs["output"] = result["output"]
            return result
        elif action == "get_issue_by_key":
            result = self.get_issue_by_key(args)
            # Log outputs to trace
            trace.outputs["output"] = result["output"]
            return result
        elif action == "close_issue":  # Updated from "close_issue"
            result = self.close_issue(args)
            # Log outputs to trace
            trace.outputs["output"] = result["output"]
            return result
        elif action == "update_issue_priority":
            result = self.update_issue_priority(args)
            # Log outputs to trace
            trace.outputs["output"] = result["output"]
            return result
        elif action == "get_issues_by_reporter":
            result = self.get_issues_by_reporter(args)
            # Log outputs to trace
            trace.outputs["output"] = result["output"]
            return result
        else:
            logger.error(f"Invalid action: {action}")
            raise ValueError(f"Invalid action: {action}")

    def find_user_account_id(self, email):
        """
        Finds the accountId of a user based on their email address.
        :param email: The email address of the user.
        :return: The accountId of the user.
        :raises ValueError: If no user is found or an error occurs.
        """
        logger.debug(f"Searching for user with email: {email}")
        try:
            users = self.jira.user_find_by_user_string(query=email, start=0, limit=1, include_inactive_users=False)
            if not users:
                message = f"No user found with email: {email}"
                logger.error(message)
                return {
                    "output": {
                        "status": "ko",
                        "message": message,
                        "email": email
                    }
                }
            account_id = users[0]["accountId"]
            logger.debug(f"Found accountId for user with email {email}: {account_id}")
            
            return {
                "output": {
                    "message": "Found accountId for user with email {email}: {account_id}",
                    "account_id": account_id,
                    "email": email
                }
            }
        except Exception as e:
            message = f"Failed to find user with email {email} -  error message: {str(e)}"
            logger.error(message)
            return {
                    "output": {
                        "status": "ko",
                        "message": message,
                        "email": email
                    }
                }


    def find_user_display_name_by_account_id(self, account_id):
        """
        Finds the display name of a user based on their accountId.
        :param account_id: The accountId of the user.
        :return: The display name of the user.
        :raises ValueError: If no user is found or an error occurs.
        """
        logger.debug(f"Searching for user with accountId: {account_id}")
        try:
            users = self.jira.user_find_by_user_string(account_id=account_id)
            if not users:
                logger.error(f"No user found with accountId: {account_id}")
                raise ValueError(f"No user found with accountId: {account_id}")
            display_name = users[0]["displayName"]
            logger.debug(f"Found display name for accountId {account_id}: {display_name}")
            return {
                "output": {
                    "message": "Found display name for accountId {account_id}: {display_name}",
                    "account_id": account_id,
                    "display_name": display_name
                }
            }
        except Exception as e:
            logger.error(f"Error finding user with accountId {account_id}: {str(e)}")
            raise ValueError(f"Failed to find user with accountId {account_id}: {str(e)}")

    def create_issue(self, args):
        logger.debug("Starting 'create_issue' action.")
        required_fields = ["reporter", "issuetype", "summary", "description"]
        for field in required_fields:
            if field not in args:
                logger.error(f"Missing required field: {field}")
                raise ValueError(f"Missing required field: {field}")

        # Validate the  priority value
        valid_priority_priorities = ["Lowest", "Low", "Medium", "High", "Highest"]
        priority = args["priority"]
        if priority not in valid_priority_priorities:
            message = f"Invalid priority value: {priority}. Must be one of {valid_priority_priorities}"
            logger.error(message)
            return {
                    "output": {
                        "status": "ko",
                        "message": message
                    }
                }
        
        # Validate the  priority value
        valid_issuetype_priorities = self.issue_types
        issuetype = args["issuetype"]
        if issuetype not in valid_issuetype_priorities:
            message = f"Invalid priority value: {issuetype}. Must be one of {valid_issuetype_priorities}"
            logger.error(message)
            return {
                        "output": {
                            "status": "ko",
                            "message": message
                        }
                    }

        # Find the accountId of the reporter using their email
        reporter_email = args["reporter"]
        response = self.find_user_account_id(reporter_email)
        if response.get("ouput",{}).get("status","ok"):
            reporter_account_id = response["output"]["account_id"]
        else:
            return {
                        "output": {
                            "status": "ko",
                            "message": response.get("ouput",{}).get("message", "There was a problem while trying to find the reporter's account ID before creating the issue...")
                        }
                    }

        # Use the provided issuetype or default to 'Email request'
        issuetype = args.get("issuetype", "Email request")

        # Simplified issue_data structure
        issue_data = {
            "project": {"key": self.jira_project_key},
            "reporter": {"accountId": reporter_account_id},
            "summary": args["summary"],
            "description": args["description"],
            "issuetype": {"name": issuetype},
            "priority": {"name": args.get("priority", "Medium")}
        }

        logger.debug(f"Issue data to be sent: {issue_data}")

        try:
            issue = self.jira.issue_create(fields=issue_data)
            logger.info(f"Issue created successfully: {issue['key']}")
            return {
                "output": {
                    "message": "Issue created successfully",
                    "issue_key": issue["key"],
                    "url": f"{self.jira_instance_url}/browse/{issue['key']}"
                }
            }
        except Exception as e:
            message = f"Error creating issue - error: {str(e)}"
            logger.error(message)
            return {
                        "output": {
                            "status": "ko",
                            "message": message
                        }
                    }

    def get_issue_by_key(self, args):
        logger.debug("Starting 'get_issue_by_key' action.")
        if "issue_key" not in args or "reporter" not in args:
            logger.error("Missing required fields: issue_key or reporter")
            raise ValueError("Missing required fields: issue_key or reporter")

        try:
            logger.debug(f"Fetching issue with key: {args['issue_key']}")
            issue = self.jira.issue(args["issue_key"])
            logger.info(f"Issue retrieved successfully: {args['issue_key']}")

            # Extract additional details
            reporter_account_id = issue["fields"]["reporter"]["accountId"]
            reporter_display_name = self.find_user_display_name_by_account_id(reporter_account_id)
            summary = issue["fields"]["summary"]
            status = issue["fields"]["status"]["name"]
            priority = issue["fields"]["priority"]["name"]

            # Find the accountId of the provided reporter email
            reporter_email = args["reporter"]
            provided_reporter_account_id = self.find_user_account_id(reporter_email)
            logger.debug(f"Provided reporter accountId: {provided_reporter_account_id}")

            # Verify the reporter
            if reporter_account_id != provided_reporter_account_id:
                logger.error("Provided reporter does not match the reporter in the issue.")
                raise ValueError("Provided reporter does not match the reporter in the issue.")

            return {
                "output": {
                    "message": "Issue retrieved successfully",
                    "issue_key": issue["key"],
                    "url": f"{self.jira_instance_url}/browse/{issue['key']}",
                    "reporter_display_name": reporter_display_name,
                    "summary": summary,
                    "status": status,
                    "priority": priority,
                    "issue": issue
                }
            }
        except Exception as e:
            logger.error(f"Error retrieving issue: {str(e)}")
            raise

    def close_issue(self, args):
        logger.debug("Starting 'close_issue' action.")
        if "issue_key" not in args or "reporter" not in args:
            logger.error("Missing required fields: issue_key or reporter")
            raise ValueError("Missing required fields: issue_key or reporter")

        try:
            # Fetch the issue details
            issue = self.jira.issue(args["issue_key"])
            issue_reporter_account_id = issue["fields"]["reporter"]["accountId"]
            logger.debug(f"Reporter accountId in issue: {issue_reporter_account_id}")

            # Find the accountId of the provided reporter email
            reporter_email = args["reporter"]
            provided_reporter_account_id = self.find_user_account_id(reporter_email)
            logger.debug(f"Provided reporter accountId: {provided_reporter_account_id}")

            # Verify the reporter
            if issue_reporter_account_id != provided_reporter_account_id:
                logger.error("Provided reporter does not match the reporter in the issue.")
                raise ValueError("Provided reporter does not match the reporter in the issue.")

            # Close the issue
            logger.debug(f"Closing issue with key: {args['issue_key']}")
            issue = self.jira.set_issue_status(args["issue_key"], "Closed")
            logger.info(f"Issue closed successfully: {args['issue_key']}")

            # Add a comment indicating the activity was done on behalf of the reporter
            comment = f"Issue closed on behalf of the reporter {reporter_email}."
            self.jira.issue_add_comment(args["issue_key"], comment)
            logger.debug(f"Added comment to issue {args['issue_key']}: {comment}")
            issue_key = args["issue_key"]

            return {
                "output": {
                    "message": "Issue closed successfully",
                    "issue_key": issue_key,
                    "url": f"{self.jira_instance_url}/browse/{issue_key}",
                    "issue": issue
                }
            }
        except Exception as e:
            logger.error(f"Error closing issue: {str(e)}")
            raise

    def update_issue_priority(self, args):
        logger.debug("Starting 'update_issue_priority' action.")
        if "issue_key" not in args or "priority" not in args or "reporter" not in args:
            logger.error("Missing required fields: issue_key, priority, or reporter")
            raise ValueError("Missing required fields: issue_key, priority, or reporter")

        # Validate the new priority value
        valid_priorities = ["Lowest", "Low", "Medium", "High", "Highest"]
        new_priority = args["priority"]
        if new_priority not in valid_priorities:
            logger.error(f"Invalid priority value: {new_priority}. Must be one of {valid_priorities}")
            raise ValueError(f"Invalid priority value: {new_priority}. Must be one of {valid_priorities}")

        try:
            # Fetch the issue details
            issue = self.jira.issue(args["issue_key"])
            issue_reporter_account_id = issue["fields"]["reporter"]["accountId"]
            logger.debug(f"Reporter accountId in issue: {issue_reporter_account_id}")

            # Find the accountId of the provided reporter email
            reporter_email = args["reporter"]
            provided_reporter_account_id = self.find_user_account_id(reporter_email)
            logger.debug(f"Provided reporter accountId: {provided_reporter_account_id}")

            # Verify the reporter
            if issue_reporter_account_id != provided_reporter_account_id:
                logger.error("Provided reporter does not match the reporter in the issue.")
                raise ValueError("Provided reporter does not match the reporter in the issue.")

            # Check the current priority
            current_priority = issue["fields"]["priority"]["name"]
            logger.debug(f"Current priority of issue {args['issue_key']}: {current_priority}")

            if current_priority == new_priority:
                logger.info(f"Priority for issue {args['issue_key']} is already set to {new_priority}. No update needed.")
                return {
                    "output": {
                        "message": f"Priority for issue {args['issue_key']} is already set to {new_priority}. No update needed."
                    }
                }

            # Update the priority
            logger.debug(f"Updating priority for issue key: {args['issue_key']} to {new_priority}")
            priority_data = {"priority": {"name": new_priority}}
            issue = self.jira.issue_update(args["issue_key"], priority_data)
            logger.info(f"Issue priority updated successfully: {args['issue_key']}")

            # Add a comment indicating the activity was done on behalf of the reporter
            comment = f"Priority updated to {new_priority} on behalf of the reporter {reporter_email}."
            self.jira.issue_add_comment(args["issue_key"], comment)
            logger.debug(f"Added comment to issue {args['issue_key']}: {comment}")
            issue_key = args["issue_key"]

            return {
                "output": {
                    "message": "Issue priority updated successfully",
                    "issue_key": issue_key,
                    "url": f"{self.jira_instance_url}/browse/{issue_key}",
                    "priority": new_priority,
                    "issue": issue
                }
            }
        except Exception as e:
            logger.error(f"Error updating issue priority: {str(e)}")
            raise

    def get_issues_by_reporter(self, args):
        logger.debug("Starting 'get_issues_by_reporter' action.")
        if "reporter" not in args:
            logger.error("Missing required field: reporter")
            raise ValueError("Missing required field: reporter")

        try:
            # Find the accountId of the provided reporter email
            reporter_email = args["reporter"]
            reporter_account_id = self.find_user_account_id(reporter_email)
            logger.debug(f"Found accountId for reporter {reporter_email}: {reporter_account_id}")

            # Search for issues reported by the user
            jql_query = f"reporter = {reporter_account_id} ORDER BY issuekey"
            logger.debug(f"Executing JQL query: {jql_query}")
            issues = self.jira.jql(jql_query)["issues"]
            logger.info(f"Found {len(issues)} issues reported by {reporter_email}")

            # Format the output
            formatted_issues = []
            for issue in issues:
                reporter_account_id = issue["fields"]["reporter"]["accountId"]
                reporter_display_name = self.find_user_display_name_by_account_id(reporter_account_id)
                formatted_issues.append({
                    "issue_key": issue["key"],
                    "summary": issue["fields"]["summary"],
                    "status": issue["fields"]["status"]["name"],
                    "priority": issue["fields"]["priority"]["name"],
                    "reporter_display_name": reporter_display_name,
                    "url": f"{self.jira_instance_url}/browse/{issue['key']}"
                })

            return {
                "output": {
                    "message": f"Found {len(formatted_issues)} issues reported by {reporter_email}",
                    "issues": formatted_issues
                }
            }
        except Exception as e:
            logger.error(f"Error retrieving issues for reporter {reporter_email}: {str(e)}")
            raise

