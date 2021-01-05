# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Create SNS Topic and subscription
aws sns create-topic --name access-analyzer-kms-keys-findings

# Replace TOPIC_ARN and YOUR_EMAIL_ADDRESS
aws sns subscribe \
    --topic-arn <TOPIC_ARN> \
    --protocol email \
    --notification-endpoint <YOUR_EMAIL_ADDRESS>

# Create Lambda execution role
aws iam create-role \
    --role-name access-analyzer-kms-function-role \
    --assume-role-policy-document '{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'

# Add permissions to the Lambda executiom role
aws iam attach-role-policy \
    --role-name access-analyzer-kms-function-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam put-role-policy \
    --role-name access-analyzer-kms-function-role \
    --policy-name LambdaAccessAnalyzerKMSExecutionRole \
    --policy-document file://lambda-function-access-analyzer-KMS-permissions.json

# Create Lambda function
# Replace ROLE_ARN with the ARN from aws iam create-role call
# Replace TOPIC_ARN with the ARN from aws sns create-topic call
aws lambda create-function \
    --function-name access-analyzer-kms-function \
    --runtime python3.8 \
    --handler lambda_function.lambda_handler \
    --role <ROLE_ARN> \
    --timeout 120 \
    --environment Variables={SNS_TOPIC_ARN=<TOPIC_ARN>} \
    --zip-file fileb://lambda_function.zip

# Create CloudWatch Events rule and link the Lambda function
aws events put-rule \
    --name kms-key-access-changes \
    --event-pattern "{\"source\": [\"aws.kms\"],\"detail-type\": [\"AWS API Call via CloudTrail\"],\"detail\": {\"eventSource\": [\"kms.amazonaws.com\"],\"eventName\": [\"PutKeyPolicy\",\"CreateGrant\"]}}" 

# Add resource-based permission to the Lambda function
# Replace RULE_ARN with the ARN returned from the aws events put-rule call
aws lambda add-permission \
    --function-name access-analyzer-kms-function \
    --statement-id CloudWatchEventsRuleLambdaPermission \
    --action 'lambda:InvokeFunction' \
    --principal events.amazonaws.com \
    --source-arn <RULE_ARN>

# Link the CloudWatch Events rule and the Lambda function
# Replace FUNCTION_ARN with the Lambda function ARN from the aws lambda create-function call
aws events put-targets \
    --rule kms-key-access-changes \
    --targets "Id"="1","Arn"="<FUNCTION_ARN>"

# Test the solution
aws kms create-key \
    --description "Access Analyzer KMS customer key scan test"

# Replace KEY_ID with the value returned by aws kms create-key call
# Replace ACCOUNT_ID 
aws kms put-key-policy \
    --key-id <KEY_ID> \
    --policy-name default \
    --policy "{\"Version\": \"2012-10-17\",\"Id\": \"key-default-policy\",\"Statement\": [{\"Sid\": \"Enable IAM User Permissions\",\"Effect\": \"Allow\",\"Principal\": {\"AWS\": [\"arn:aws:iam::ACCOUNT_ID:root\",\"*\"]},\"Action\": \"kms:*\",\"Resource\": \"*\"}]}"

aws kms put-key-policy \
    --key-id <KEY_ID> \
    --policy-name default \
    --policy "{\"Version\": \"2012-10-17\",\"Id\": \"key-default-policy\",\"Statement\": [{\"Sid\": \"Enable IAM User Permissions\",\"Effect\": \"Allow\",\"Principal\": {\"AWS\": [\"arn:aws:iam::ACCOUNT_ID:root\"]},\"Action\": \"kms:*\",\"Resource\": \"*\"}]}"


