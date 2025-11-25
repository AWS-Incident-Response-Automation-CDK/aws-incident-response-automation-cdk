#!/usr/bin/env python3
import os

import aws_cdk as cdk

from aws_incident_response_automation_cdk.aws_incident_response_automation_cdk_stack import AwsIncidentResponseAutomationCdkStack


app = cdk.App()
AwsIncidentResponseAutomationCdkStack(app, "AwsIncidentResponseAutomationCdkStack",
    env=cdk.Environment(account='831981618496', region='ap-southeast-1'),
    )
app.synth()
