# access-analyzer-kms

Code repository for the security blog post about detecting the public access to the KMS customer keys using IAM Access Analyzer

![access analyzer KMS public access detection](design/access-analyzer.drawio.svg)

## Repository structure
- `artefacts/`: samples of Access Analyzer output and email content example  
- `cli/`: AWS CLI commands to deploy the whole solution manually (an alternative to SAM template)
- `events/`: CloudWatch Events rule setup
- `functions/`: Lambda function
- `policies/`: Lambda execution role policies and KMS keys policies

## Deployment
You can choose to deploy the solution either as Serverless Application Model (SAM) application via SAM CLI or manually via command line using AWS CLI.
Both methods require Administrator access to your account.

### Serverless Application Model (SAM) deployment
The solution is delivered as a SAM application. Follow the instructions to deploy the solution to your AWS account:

1. Install [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html) if you do not have it
2. Clone the source code repository to your local environment
3. Build and deploy solution using the SAM CLI in the solution directory:
```bash
% sam build
```
```bash
% sam deploy --guided
```

### Manual deployment
Alternatively, you can deploy the solution step by step by executing the following command line statements.

1. Clone the source code repository to your local enviroment
```bash
git clone <git-repository>
cd access-analyzer-kms
```

2. Create SNS topic and subscription
```bash
aws sns create-topic --name access-analyzer-kms-keys-findings
```

Replace `TOPIC_ARN` with the SNS topic arn returned from the previous command and `YOUR_EMAIL_ADDRESS` with your email address
```bash
aws sns subscribe \
    --topic-arn <TOPIC_ARN> \
    --protocol email \
    --notification-endpoint <YOUR_EMAIL_ADDRESS>
```

3. Create Lambda execution role and Lambda function
```bash
aws iam create-role \
    --role-name access-analyzer-kms-function-role \
    --assume-role-policy-document '{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
```

Attach the AWS managed policy to the Lambda execution role:
```bash
aws iam attach-role-policy \
    --role-name access-analyzer-kms-function-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

Attach the custom policy for specific permissions. Replace `SNS_TOPIC_ARN` and `ACCOUNT_ID` placeholder in the file [lambda-function-access-analyzer-KMS-permissions.json](policies/lambda-function-access-analyzer-KMS-permissions.json):
```bash
aws iam put-role-policy \
    --role-name access-analyzer-kms-function-role \
    --policy-name LambdaAccessAnalyzerKMSExecutionRole \
    --policy-document file://policies/lambda-function-access-analyzer-KMS-permissions.json
```

Create the Lambda function. Replace `ROLE_ARN` with the ARN from `aws iam create-role` call and `TOPIC_ARN` with the ARN from `aws sns create-topic` call:
```bash
aws lambda create-function \
    --function-name access-analyzer-kms-function \
    --runtime python3.8 \
    --handler lambda_function.lambda_handler \
    --role <ROLE_ARN> \
    --timeout 120 \
    --environment Variables={SNS_TOPIC_ARN=<TOPIC_ARN>} \
    --zip-file fileb://cli/lambda_function.zip
```

4. Create a CloudWatch Events rule and wire it to the Lambda function
```bash
aws events put-rule \
    --name kms-key-access-changes \
    --event-pattern "{\"source\": [\"aws.kms\"],\"detail-type\": [\"AWS API Call via CloudTrail\"],\"detail\": {\"eventSource\": [\"kms.amazonaws.com\"],\"eventName\": [\"PutKeyPolicy\",\"CreateGrant\"]}}" 
```

Allow the CloudWatch Events rule to invoke our Lambda function. Replace `RULE_ARN` with the ARN returned from the `aws events put-rule` call:
```bash
aws lambda add-permission \
    --function-name access-analyzer-kms-function \
    --statement-id CloudWatchEventsRuleLambdaPermission \
    --action 'lambda:InvokeFunction' \
    --principal events.amazonaws.com \
    --source-arn <RULE_ARN>
```

Link the rule and the function (target). Replace `FUNCTION_ARN` with the Lambda function ARN from the `aws lambda create-function` call:
```bash
aws events put-targets \
    --rule kms-key-access-changes \
    --targets "Id"="1","Arn"="<FUNCTION_ARN>"
```

## Test detection of public access for AWS KMS key polices
Create a KMS key:
```bash
aws kms create-key \
    --description "Access Analyzer KMS customer key scan test"
```

Make the key public by adding `"*"` to the allowed principal list. Replace `KEY_ID` with the value returned by `aws kms create-key` call. Replace `ACCOUNT_ID`:
```bash
aws kms put-key-policy \
    --key-id <KEY_ID> \
    --policy-name default \
    --policy "{\"Version\": \"2012-10-17\",\"Id\": \"key-default-policy\",\"Statement\": [{\"Sid\": \"Enable IAM User Permissions\",\"Effect\": \"Allow\",\"Principal\": {\"AWS\": [\"arn:aws:iam::ACCOUNT_ID:root\",\"*\"]},\"Action\": \"kms:*\",\"Resource\": \"*\"}]}"
```

Check your email. You will receive a notification from the Lambda function about public access to your KMS key.

Set the policy to private again. Replace `KEY_ID` with the value returned by `aws kms create-key` call. Replace `ACCOUNT_ID`:
```bash
aws kms put-key-policy \
    --key-id <KEY_ID> \
    --policy-name default \
    --policy "{\"Version\": \"2012-10-17\",\"Id\": \"key-default-policy\",\"Statement\": [{\"Sid\": \"Enable IAM User Permissions\",\"Effect\": \"Allow\",\"Principal\": {\"AWS\": [\"arn:aws:iam::906545278380:root\"]},\"Action\": \"kms:*\",\"Resource\": \"*\"}]}"
```





Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0