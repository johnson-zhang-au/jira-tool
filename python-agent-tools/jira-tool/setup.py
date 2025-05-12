from setuptools import setup, find_packages

setup(
    name="jira-tool",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "jira",
        "python-dotenv",
    ],
    python_requires=">=3.11",
) 