# access-analyzer-kms

Code repository for the security blog post about detecting the public access to the KMS customer keys using IAM Access Analyzer

![access analyzer KMS public access detection](design/access-analyzer.drawio.svg)

## Repository structure
- `artefacts/`: samples of Access Analyzer output and email content example  
- `cli/`: AWS CLI commands to deploy the whole solution manually (an alternative to SAM template)
- `events/`: CloudWatch Events rule setup
- `functions/`: Lambda function
- `policies/`: Lambda execution role policies and KMS keys policies

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0