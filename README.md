
## AWS Incident Response Automation Stack Deployment Guide

This document provides step-by-step instructions for deploying the AWS Incident Response Automation CDK stack in your AWS Account.

### AWS Configuration Setup

Before deploying the CDK stack, you must configure your local environment to authenticate with your AWS account using the **AWS Command Line Interface (CLI)**.

1.  **Install the AWS CLI**.
2.  **Obtain Credentials:** You need an **Access Key ID** and a **Secret Access Key** from an IAM user with deployment permissions.
3.  **Run the Configuration Command:** Open your terminal and execute `aws configure`.
    ```bash
    $ aws configure
    ```
    When prompted, enter your credentials and desired settings. The **Default region name** should match the region where you plan to deploy the stack (e.g., `ap-southeast-1`):

    | Prompt | Example Value |
    | :--- | :--- |
    | `AWS Access Key ID` | `AKIA...` |
    | `AWS Secret Access Key` | `wJalr...` |
    | `Default region name` | `ap-southeast-1` |
    | `Default output format` | `json` |

4.  **Verify Configuration:** Test your setup by fetching your user identity. A successful output confirms you are authenticated.
    ```bash
    $ aws sts get-caller-identity
    ```

---
### Prerequisites

Ensure the following tools and services are installed and configured on your system:

1.  **Python 3.8+ and pip:** Required for executing the CDK application and building Lambda function assets.
2.  **Node.js and npm:** Required for running the AWS CDK CLI and building the React dashboard.
3.  **AWS CDK Toolkit:** Install the CDK CLI globally:
    ```bash
    $ npm install -g aws-cdk
    ```
5.  **CDK Bootstrapping:** If you have not used the **AWS CDK** in your target AWS account and region previously, run the bootstrap command once to provision necessary resources (e.g., S3 deployment bucket).
    ```bash
    $ cdk bootstrap
    ```
---

### Step 1: Set Up Python Environment

The infrastructure definition is written in **Python**. A dedicated **virtual environment** is used to manage project dependencies.

1.  **Create the Virtual Environment** (Skip if the `.venv` directory exists):
    ```bash
    $ python -m venv .venv
    ```
2.  **Activate the Virtual Environment**:

    | Operating System | Command |
    | :--- | :--- |
    | **macOS / Linux** | `source .venv/bin/activate` |
    | **Windows (Command Prompt)** | `.venv\Scripts\activate.bat` |
    | **Windows (PowerShell)** | `.venv\Scripts\Activate.ps1` |

3.  **Install Python Dependencies**:
    ```bash
    $ pip install -r requirements.txt
    ```

---

### Step to build the dashboard

**Check inside the `react` folder. If the `dist` folder already exists, you do not need to build. Otherwise, please follow the steps below.**

## Prerequisites
Ensure you have **Node.js** and **npm** installed. You can check the current version by running:
```
$ npm --version
```
If the command is not recognized, please download and install Node.js from [nodejs.org](https://nodejs.org/en)

## Install dependencies
Run the following command to install all necessary libraries:
```
$ npm install
```

## Build the Project
After the installation is complete, run the build command:
```
$ npm run build
```
Upon completion, a dist folder will be generated containing index.html and the assets folder.

### Configure Deployment Context

The stack utilizes context variables. These variables are read from `cdk.context.json` or provided via command-line flags.

| Variable Name | Description | Required if functionality is desired | Default Value (in `cdk.context.json`) |
| :--- | :--- | :--- | :--- |
| `vpc_ids` | A list of VPC IDs for Flow Logs and DNS Query Logging. | Yes | `[]` |
| `alert_email` | A list of email addresses for alert notifications (requires SES). | Yes | `[]` |
| `sender_email` | The verified SES sender email address. | Yes (if `alert_email` is set) | `""` |
| `slack_webhook_url` | The Slack webhook URL for sending alerts. | No | `""` |

**Example**
```json
{
    "vpc_ids": [
        "vpc-a1b2c3d4e5f6g7h8i"
    ],
    "alert_email": [
        "admin@example.com"
    ],
    "sender_email": "alerts@your-domain.com",
    "slack_webhook_url": ""
}
```

### Deploy the Stacks

1.  **(Optional) Synthesize and Diff:** Review the proposed CloudFormation changes before deployment:
    ```bash
    $ cdk synth --all
    $ cdk diff --all
    ```

2.  **Execute Deployment:** Run the deployment command and approve any requested **IAM security changes** when prompted.
    ```bash
    $ cdk deploy --all
    ```

The deployment is complete when the CDK CLI reports success for the stack: `AwsIncidentResponseAutomationCdkStack` and `DashboardCdkStack` 