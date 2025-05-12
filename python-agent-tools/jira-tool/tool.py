from dataiku.llm.agent_tools import BaseAgentTool
from atlassian import Jira
from utils.logging import logger  # Import the LazyLogger class
import traceback  # Add traceback module import

class JiraTool(BaseAgentTool):
    def set_config(self, config, plugin_config):
        """Initialize the Jira tool with configuration."""
        self._validate_config(config)
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

    def _validate_config(self, config):
        """Validate the configuration values."""
        required_fields = {
            "jira_api_connection": {
                "jira_instance_url": str,
                "jira_username": str,
                "jira_api_token": str,
                "jira_project_key": str,
                "jira_cloud": bool,
                "issue_types": list
            }
        }

        if "jira_api_connection" not in config:
            raise ValueError("Missing required configuration section: jira_api_connection")

        connection_config = config["jira_api_connection"]
        for field, field_type in required_fields["jira_api_connection"].items():
            if field not in connection_config:
                raise ValueError(f"Missing required configuration field: {field}")
            if not isinstance(connection_config[field], field_type):
                raise ValueError(f"Invalid type for {field}. Expected {field_type.__name__}, got {type(connection_config[field]).__name__}")

        # Validate URL format
        url = connection_config["jira_instance_url"]
        if not url.startswith(("http://", "https://")):
            raise ValueError("jira_instance_url must start with http:// or https://")

        # Validate issue types
        if not connection_config["issue_types"]:
            raise ValueError("issue_types must not be empty")

    def _create_error_response(self, message, **kwargs):
        """
        Creates a standardized error response.
        :param message: The error message
        :param kwargs: Additional fields to include in the response
        :return: Standardized error response dictionary
        """
        logger.error(message)
        response = {
            "output": {
                "action_status": "ko",
                "message": message
            }
        }
        response["output"].update(kwargs)
        return response

    def _create_error_response_with_traceback(self, message, error, **kwargs):
        """
        Creates a standardized error response with traceback information.
        :param message: The error message
        :param error: The exception object
        :param kwargs: Additional fields to include in the response
        :return: Standardized error response dictionary
        """
        # Get the traceback information
        tb = traceback.extract_tb(error.__traceback__)
        if tb:
            # Get the last frame (where the error occurred)
            last_frame = tb[-1]
            error_location = f"{last_frame.filename}:{last_frame.lineno}"
            error_context = f"in {last_frame.name}"
            error_line = last_frame.line
        else:
            error_location = "unknown"
            error_context = "unknown"
            error_line = "unknown"

        # Create the detailed error message
        detailed_message = f"{message}\nError occurred at {error_location} {error_context}\nLine: {error_line}\nError: {str(error)}"
        logger.error(detailed_message)

        response = {
            "output": {
                "action_status": "ko",
                "message": message,
                "error_details": {
                    "location": error_location,
                    "context": error_context,
                    "line": error_line,
                    "error": str(error)
                }
            }
        }
        response["output"].update(kwargs)
        return response

    def _create_success_response(self, message, **kwargs):
        """
        Creates a standardized success response.
        :param message: The success message
        :param kwargs: Additional fields to include in the response
        :return: Standardized success response dictionary
        """
        logger.info(message)
        response = {
            "output": {
                "action_status": "ok",
                "message": message
            }
        }
        response["output"].update(kwargs)
        return response

    def validate_priority(self, priority):
        """
        Validates if the provided priority is valid.
        :param priority: The priority value to validate
        :return: None if valid, error response if invalid
        """
        valid_priorities = ["Lowest", "Low", "Medium", "High", "Highest"]
        if priority not in valid_priorities:
            return self._create_error_response(
                f"Invalid priority value: {priority}. Must be one of {valid_priorities}"
            )
        return None

    def verify_reporter(self, issue_reporter_id, provided_reporter_email):
        """
        Verifies if the provided reporter matches the issue reporter.
        :param issue_reporter_id: The account ID of the issue reporter
        :param provided_reporter_email: The email of the provided reporter
        :return: None if verified, error response if not verified
        """
        provided_reporter_response = self.find_user_account_id({"email": provided_reporter_email})
        if provided_reporter_response["output"]["action_status"] == "ko":
            return provided_reporter_response
        provided_reporter_id = provided_reporter_response["output"]["account_id"]
        
        if issue_reporter_id != provided_reporter_id:
            return self._create_error_response(
                f"Forbidden!!! Provided reporter {provided_reporter_email} does not match the reporter in the issue."
            )
        return None

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
                        "enum": ["create_issue", "get_issue_by_key", "close_issue", "update_issue_priority", "get_issues_by_reporter", "find_user_account_id", "find_user_display_name_by_account_id", "find_user_display_name_by_email"],
                        "description": "The action to perform (create_issue, get_issue_by_key, close_issue, update_issue_priority, get_issues_by_reporter, find_user_account_id, find_user_display_name_by_account_id, or find_user_display_name_by_email)"
                    },
                    "issue_key": {
                        "type": "string",
                        "description": "Issue key (required for get_issue_by_key, close_issue, and update_issue_priority actions)"
                    },
                    "reporter": {
                        "type": "string",
                        "description": "Reporter's email address (required for create_issue, get_issue_by_key, close_issue, update_issue_priority, and get_issues_by_reporter actions)"
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
                        "description": "Issue priority (required for create_issue and update_issue_priority actions)"
                    },
                    "issuetype": {
                        "type": "string",
                        "enum": self.issue_types,
                        "description": f"Issue type (required for create_issue action, must be one of: {', '.join(self.issue_types)})"
                    },
                    "email": {
                        "type": "string",
                        "description": "Email address of the user (required for find_user_account_id and find_user_display_name_by_email actions)"
                    },
                    "account_id": {
                        "type": "string",
                        "description": "Account ID of the user (required for find_user_display_name_by_account_id action)"
                    }
                },
                "required": ["action"]
            }
        }

    def check_required_fields(self, args, required_fields):
        """
        Checks if all required fields are present in the input arguments.
        :param args: The input arguments dictionary
        :param required_fields: List of required field names
        :return: None if all fields are present, error response if any are missing
        """
        missing_fields = [field for field in required_fields if field not in args]
        if missing_fields:
            return self._create_error_response(
                f"Missing required fields: {', '.join(missing_fields)}",
                missing_fields=missing_fields
            )
        return None

    def invoke(self, input, trace):
        """
        Invokes the appropriate action based on the input.
        :param input: Dictionary containing the input parameters
        :param trace: Trace object for logging
        :return: Response from the invoked action
        """
        if not input or not isinstance(input, dict):
            return self._create_error_response("Invalid input: input must be a dictionary")

        if "input" not in input:
            return self._create_error_response("Invalid input: missing 'input' field")

        args = input["input"]
        if not isinstance(args, dict):
            return self._create_error_response("Invalid input: 'input' field must be a dictionary")

        if "action" not in args:
            return self._create_error_response("Invalid input: missing 'action' field")

        action = args["action"]
        if not isinstance(action, str):
            return self._create_error_response("Invalid input: 'action' field must be a string")

        logger.info(f"Invoking action: {action}")
        logger.debug(f"Input arguments: {args}")
        
        # Log inputs and config to trace
        trace.span["name"] = "JIRA_TOOL_CALL"
        for key, value in args.items():
            trace.inputs[key] = value
        # Mask sensitive information in config
        masked_config = self.config.copy()
        if "jira_api_connection" in masked_config:
            masked_config["jira_api_connection"] = masked_config["jira_api_connection"].copy()
            token = masked_config["jira_api_connection"]["jira_api_token"]
            if token and len(token) > 8:
                masked_token = f"{token[:4]}...{token[-4:]}"
            else:
                masked_token = "********"
            masked_config["jira_api_connection"]["jira_api_token"] = masked_token
        trace.attributes["config"] = masked_config

        result = None
        if action == "create_issue":
            result = self.create_issue(args)
        elif action == "get_issue_by_key":
            result = self.get_issue_by_key(args)
        elif action == "close_issue":
            result = self.close_issue(args)
        elif action == "update_issue_priority":
            result = self.update_issue_priority(args)
        elif action == "get_issues_by_reporter":
            result = self.get_issues_by_reporter(args)
        elif action == "find_user_account_id":
            result = self.find_user_account_id(args)
        elif action == "find_user_display_name_by_account_id":
            result = self.find_user_display_name_by_account_id(args)
        elif action == "find_user_display_name_by_email":
            result = self.find_user_display_name_by_email(args)
        else:
            result = self._create_error_response(f"Invalid action: {action}")

        # Log outputs to trace
        trace.outputs["output"] = result["output"]
        return result

    def find_user_account_id(self, args):
        """
        Finds the accountId of a user based on their email address.
        :param args: Dictionary containing email
        :return: The accountId of the user.
        :raises ValueError: If no user is found or an error occurs.
        """
        required_fields = ["email"]
        error_response = self.check_required_fields(args, required_fields)
        if error_response:
            return error_response

        email = args["email"]
        logger.debug(f"Searching for user with email: {email}")
        try:
            users = self.jira.user_find_by_user_string(query=email, start=0, limit=1, include_inactive_users=False)
            if not users:
                return self._create_error_response(
                    f"No user found with email: {email}",
                    email=email
                )
            account_id = users[0]["accountId"]
            logger.debug(f"Found accountId for user with email {email}: {account_id}")
            
            return self._create_success_response(
                f"Found accountId for user with email {email}: {account_id}",
                account_id=account_id,
                email=email
            )
        except Exception as e:
            return self._create_error_response_with_traceback(
                f"Failed to find user with email {email}",
                e
            )

    def find_user_display_name_by_account_id(self, args):
        """
        Finds the display name of a user based on their accountId.
        :param args: Dictionary containing account_id
        :return: The display name of the user.
        """
        required_fields = ["account_id"]
        error_response = self.check_required_fields(args, required_fields)
        if error_response:
            return error_response

        account_id = args["account_id"]
        logger.debug(f"Searching for user with accountId: {account_id}")
        
        # Check if the provided account_id looks like an email
        if '@' in account_id:
            message = f"The provided value '{account_id}' appears to be an email address. Please use the find_user_account_id action first to get the account ID."
            logger.error(message)
            return self._create_error_response(message)

        try:
            users = self.jira.user_find_by_user_string(account_id=account_id)
            if not users:
                return self._create_error_response(f"No user found with accountId: {account_id}")
            display_name = users[0]["displayName"]
            logger.debug(f"Found display name for accountId {account_id}: {display_name}")
            return self._create_success_response(
                f"Found display name for accountId {account_id}: {display_name}",
                account_id=account_id,
                display_name=display_name
            )
        except Exception as e:
            return self._create_error_response_with_traceback(
                f"Error finding user with accountId {account_id}",
                e
            )

    def find_user_display_name_by_email(self, args):
        """
        Finds the display name of a user based on their email address.
        :param args: Dictionary containing email
        :return: The display name of the user.
        """
        required_fields = ["email"]
        error_response = self.check_required_fields(args, required_fields)
        if error_response:
            return error_response

        email = args["email"]
        logger.debug(f"Searching for user display name with email: {email}")
        
        try:
            # First find the account ID
            account_id_response = self.find_user_account_id({"email": email})
            if account_id_response["output"]["action_status"] == "ko":
                return account_id_response
            
            account_id = account_id_response["output"]["account_id"]
            
            # Then find the display name
            display_name_response = self.find_user_display_name_by_account_id({"account_id": account_id})
            if display_name_response["output"]["action_status"] == "ko":
                return display_name_response
                
            display_name = display_name_response["output"]["display_name"]
            
            return self._create_success_response(
                f"Found display name for email {email}: {display_name}",
                email=email,
                account_id=account_id,
                display_name=display_name
            )
        except Exception as e:
            return self._create_error_response_with_traceback(
                f"Error finding display name for email {email}",
                e
            )

    def create_issue(self, args):
        """
        Creates a new Jira issue.
        :param args: Dictionary containing issue details
        :return: Response with created issue details
        """
        required_fields = ["reporter", "issuetype", "summary", "description"]
        error_response = self.check_required_fields(args, required_fields)
        if error_response:
            return error_response

        # Validate the priority value
        priority_validation = self.validate_priority(args.get("priority", "Medium"))
        if priority_validation:
            return priority_validation

        # Validate the issue type
        if args["issuetype"] not in self.issue_types:
            return self._create_error_response(
                f"Invalid issue type: {args['issuetype']}. Must be one of {self.issue_types}"
            )

        try:
            # Find the accountId of the reporter using their email
            reporter_email = args["reporter"]
            reporter_response = self.find_user_account_id({"email": reporter_email})
            if reporter_response["output"]["action_status"] == "ko":
                return reporter_response
            reporter_account_id = reporter_response["output"]["account_id"]
            logger.debug(f"Reporter accountId: {reporter_account_id}")

            # Get the display name of the reporter
            display_name_response = self.find_user_display_name_by_account_id({"account_id": reporter_account_id})
            if display_name_response["output"]["action_status"] == "ko":
                return display_name_response
            reporter_display_name = display_name_response["output"]["display_name"]
            logger.debug(f"Reporter display name: {reporter_display_name}")

            # Create the issue
            issue_dict = {
                "project": {"key": self.jira_project_key},
                "reporter": {"id": reporter_account_id},
                "summary": args["summary"],
                "description": args["description"],
                "issuetype": {"name": args["issuetype"]},
                "priority": {"name": args.get("priority", "Medium")}
            }
            logger.debug(f"Creating issue with data: {issue_dict}")
            new_issue = self.jira.create_issue(fields=issue_dict)
            logger.info(f"Issue created successfully: {new_issue}")

            # Get the full issue details after creation
            issue_key = new_issue["key"]
            issue = self.jira.issue(issue_key)
            
            # Extract essential issue details
            status = issue["fields"]["status"]["name"]
            priority = issue["fields"]["priority"]["name"]
            issue_type = issue["fields"]["issuetype"]["name"]
            created = issue["fields"]["created"]

            return self._create_success_response(
                "Issue created successfully",
                issue_key=issue_key,
                url=f"{self.jira_instance_url}/browse/{issue_key}",
                reporter_display_name=reporter_display_name,
                summary=args["summary"],
                status=status,
                priority=priority,
                issue_type=issue_type,
                created=created
            )
        except Exception as e:
            return self._create_error_response_with_traceback(
                f"Error creating issue",
                e
            )

    def get_issue_by_key(self, args):
        """
        Retrieves a Jira issue by its key.
        :param args: Dictionary containing issue key and reporter
        :return: Response with issue details
        """
        required_fields = ["issue_key", "reporter"]
        error_response = self.check_required_fields(args, required_fields)
        if error_response:
            return error_response

        try:
            logger.debug(f"Fetching issue with key: {args['issue_key']}")
            issue = self.jira.issue(args["issue_key"])
            logger.info(f"Issue retrieved successfully: {args['issue_key']}")

            # Extract additional details
            reporter_account_id = issue["fields"]["reporter"]["accountId"]
            reporter_display_name_response = self.find_user_display_name_by_account_id({"account_id": reporter_account_id})
            if reporter_display_name_response["output"]["action_status"] == "ko":
                return reporter_display_name_response
            reporter_display_name = reporter_display_name_response["output"]["display_name"]
            summary = issue["fields"]["summary"]
            status = issue["fields"]["status"]["name"]
            priority = issue["fields"]["priority"]["name"]
            issue_type = issue["fields"]["issuetype"]["name"]
            created = issue["fields"]["created"]

            # Find the accountId of the provided reporter email
            reporter_email = args["reporter"]
            provided_reporter_response = self.find_user_account_id({"email": reporter_email})
            if provided_reporter_response["output"]["action_status"] == "ko":
                return provided_reporter_response
            provided_reporter_account_id = provided_reporter_response["output"]["account_id"]
            logger.debug(f"Provided reporter accountId: {provided_reporter_account_id}")

            # Verify the reporter
            if reporter_account_id != provided_reporter_account_id:
                return self._create_error_response(
                    f"Forbidden!!! Provided reporter {reporter_email} does not match the reporter in the issue. Only the original reporter can access this issue."
                )

            return self._create_success_response(
                "Issue retrieved successfully",
                issue_key=issue["key"],
                url=f"{self.jira_instance_url}/browse/{issue['key']}",
                reporter_display_name=reporter_display_name,
                summary=summary,
                status=status,
                priority=priority,
                issue_type=issue_type,
                created=created
            )
        except Exception as e:
            return self._create_error_response_with_traceback(
                f"Error retrieving issue by key {args['issue_key']}",
                e
            )

    def close_issue(self, args):
        """
        Closes a Jira issue.
        :param args: Dictionary containing issue key and reporter
        :return: Response with closed issue details
        """
        required_fields = ["issue_key", "reporter"]
        error_response = self.check_required_fields(args, required_fields)
        if error_response:
            return error_response

        try:
            # Fetch the issue details
            issue = self.jira.issue(args["issue_key"])
            issue_reporter_account_id = issue["fields"]["reporter"]["accountId"]
            logger.debug(f"Reporter accountId in issue: {issue_reporter_account_id}")

            # Find the accountId of the provided reporter email
            reporter_email = args["reporter"]
            provided_reporter_response = self.find_user_account_id({"email": reporter_email})
            if provided_reporter_response["output"]["action_status"] == "ko":
                return provided_reporter_response
            provided_reporter_account_id = provided_reporter_response["output"]["account_id"]
            logger.debug(f"Provided reporter accountId: {provided_reporter_account_id}")

            # Verify the reporter
            if issue_reporter_account_id != provided_reporter_account_id:
                return self._create_error_response(
                    f"Forbidden!!! Provided reporter {reporter_email} does not match the reporter in the issue. Only the original reporter can close this issue."
                )

            # Close the issue
            logger.debug(f"Closing issue with key: {args['issue_key']}")
            issue = self.jira.set_issue_status(args["issue_key"], "Closed")
            logger.info(f"Issue closed successfully: {args['issue_key']}")

            # Add a comment indicating the activity was done on behalf of the reporter
            comment = f"Issue closed on behalf of the reporter {reporter_email}."
            self.jira.issue_add_comment(args["issue_key"], comment)
            logger.debug(f"Added comment to issue {args['issue_key']}: {comment}")

            # Get reporter display name for the response
            reporter_display_name_response = self.find_user_display_name_by_account_id({"account_id": issue_reporter_account_id})
            if reporter_display_name_response["output"]["action_status"] == "ko":
                return reporter_display_name_response
            reporter_display_name = reporter_display_name_response["output"]["display_name"]
            
            issue = self.jira.issue(args["issue_key"])

            return self._create_success_response(
                "Issue closed successfully",
                issue_key=args["issue_key"],
                url=f"{self.jira_instance_url}/browse/{args['issue_key']}",
                reporter_display_name=reporter_display_name,
                summary=issue["fields"]["summary"],
                status=issue["fields"]["status"]["name"],
                priority=issue["fields"]["priority"]["name"],
                issue_type=issue["fields"]["issuetype"]["name"],
                created=issue["fields"]["created"]
            )
        except Exception as e:
            return self._create_error_response_with_traceback(
                f"Error closing issue {args['issue_key']}",
                e
            )

    def update_issue_priority(self, args):
        """
        Updates the priority of a Jira issue.
        :param args: Dictionary containing issue key, priority, and reporter
        :return: Response with updated issue details
        """
        required_fields = ["issue_key", "priority", "reporter"]
        error_response = self.check_required_fields(args, required_fields)
        if error_response:
            return error_response

        # Validate the new priority value
        valid_priorities = ["Lowest", "Low", "Medium", "High", "Highest"]
        new_priority = args["priority"]
        if new_priority not in valid_priorities:
            return self._create_error_response(
                f"Invalid priority value: {new_priority}. Must be one of {valid_priorities}"
            )

        try:
            # Fetch the issue details
            issue = self.jira.issue(args["issue_key"])
            issue_reporter_account_id = issue["fields"]["reporter"]["accountId"]
            logger.debug(f"Reporter accountId in issue: {issue_reporter_account_id}")

            # Find the accountId of the provided reporter email
            reporter_email = args["reporter"]
            provided_reporter_response = self.find_user_account_id({"email": reporter_email})
            if provided_reporter_response["output"]["action_status"] == "ko":
                return provided_reporter_response
            provided_reporter_account_id = provided_reporter_response["output"]["account_id"]
            logger.debug(f"Provided reporter accountId: {provided_reporter_account_id}")

            # Verify the reporter
            if issue_reporter_account_id != provided_reporter_account_id:
                return self._create_error_response(
                    f"Forbidden!!! Provided reporter {reporter_email} does not match the reporter in the issue. Only the original reporter can update this issue's priority."
                )

            # Get reporter display name for the response
            reporter_display_name_response = self.find_user_display_name_by_account_id({"account_id": issue_reporter_account_id})
            if reporter_display_name_response["output"]["action_status"] == "ko":
                return reporter_display_name_response
            reporter_display_name = reporter_display_name_response["output"]["display_name"]

            # Check the current priority
            current_priority = issue["fields"]["priority"]["name"]
            logger.debug(f"Current priority of issue {args['issue_key']}: {current_priority}")

            if current_priority == new_priority:
                return self._create_success_response(
                    f"Priority for issue {args['issue_key']} is already set to {new_priority}. No update needed.",
                    issue_key=args["issue_key"],
                    url=f"{self.jira_instance_url}/browse/{args['issue_key']}",
                    reporter_display_name=reporter_display_name,
                    summary=issue["fields"]["summary"],
                    status=issue["fields"]["status"]["name"],
                    priority=new_priority,
                    issue_type=issue["fields"]["issuetype"]["name"],
                    created=issue["fields"]["created"]
                )

            # Update the priority
            logger.debug(f"Updating priority for issue key: {args['issue_key']} to {new_priority}")
            priority_data = {"priority": {"name": new_priority}}
            issue = self.jira.issue_update(args["issue_key"], priority_data)
            logger.info(f"Issue priority updated successfully: {args['issue_key']}")
            logger.debug(f"The returned issue detail after updating: {issue}")

            # Add a comment indicating the activity was done on behalf of the reporter
            comment = f"Priority updated to {new_priority} on behalf of the reporter {reporter_email}."
            self.jira.issue_add_comment(args["issue_key"], comment)
            logger.debug(f"Added comment to issue {args['issue_key']}: {comment}")
            
            issue = self.jira.issue(args["issue_key"])

            return self._create_success_response(
                "Issue priority updated successfully",
                issue_key=args["issue_key"],
                url=f"{self.jira_instance_url}/browse/{args['issue_key']}",
                reporter_display_name=reporter_display_name,
                summary=issue["fields"]["summary"],
                status=issue["fields"]["status"]["name"],
                priority=new_priority,
                issue_type=issue["fields"]["issuetype"]["name"],
                created=issue["fields"]["created"]
            )
        except Exception as e:
            return self._create_error_response_with_traceback(
                f"Error updating issue {args['issue_key']} priority",
                e
            )

    def get_issues_by_reporter(self, args):
        """
        Retrieves all issues reported by a specific user.
        :param args: Dictionary containing reporter email
        :return: Response with list of issues
        """
        required_fields = ["reporter"]
        error_response = self.check_required_fields(args, required_fields)
        if error_response:
            return error_response

        try:
            # Find the accountId of the provided reporter email
            reporter_email = args["reporter"]
            reporter_response = self.find_user_account_id({"email": reporter_email})
            if reporter_response["output"]["action_status"] == "ko":
                return reporter_response
            reporter_account_id = reporter_response["output"]["account_id"]
            logger.debug(f"Reporter accountId: {reporter_account_id}")

            # Get the display name of the reporter
            display_name_response = self.find_user_display_name_by_account_id({"account_id": reporter_account_id})
            if display_name_response["output"]["action_status"] == "ko":
                return display_name_response
            reporter_display_name = display_name_response["output"]["display_name"]
            logger.debug(f"Reporter display name: {reporter_display_name}")

            # Construct the JQL query
            jql = f'reporter = "{reporter_account_id}" ORDER BY created DESC'
            logger.debug(f"JQL query: {jql}")

            # Search for issues
            issues = self.jira.jql(jql)["issues"]
            logger.info(f"Found {len(issues)} issues for reporter {reporter_email}")

            # Format the response with essential details
            issues_list = []
            for issue in issues:
                issues_list.append({
                    "issue_key": issue["key"],
                    "url": f"{self.jira_instance_url}/browse/{issue['key']}",
                    "summary": issue["fields"]["summary"],
                    "status": issue["fields"]["status"]["name"],
                    "priority": issue["fields"]["priority"]["name"],
                    "issue_type": issue["fields"]["issuetype"]["name"],
                    "created": issue["fields"]["created"]
                })

            return self._create_success_response(
                f"Found {len(issues_list)} issues for reporter {reporter_email}",
                reporter_display_name=reporter_display_name,
                issues=issues_list
            )
        except Exception as e:
            return self._create_error_response_with_traceback(
                f"Error getting issues for reporter {args['reporter']}",
                e
            )

