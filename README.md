# Using AWS IAM Access Analyzer API to detect public access to AWS KMS CMK

Code repository for the [security blog post](link) about detecting the public access to the KMS customer keys using IAM Access Analyzer

## Solution overview

![access analyzer KMS public access detection](design/access-analyzer.drawio.svg)

1. Resources supported by AWS IAM Access Analyzer
2. AWS KMS API calls via AWS CloudTrail 
3. AWS KMS API calls are captured as Amazon EventBridge Rule 
4. EventBridge rule triggers the AWS Lambda function, which uses Access Analyzer to scan the specific resources
5. Lambda function calls Access Analyzer to scan the KMS keys. Findings are published to an EventBrige bus (5A) or to AWS Security Hub (5B)
6. Optional corrective action

## Repository structure
- `artefacts/`: samples of Access Analyzer output and email content example  
- `design/`: Architecture diagram for the solution
- `events/`: EventBridge rule setup
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
% git clone https://github.com/aws-samples/aws-iam-access-analyzer-kms-blog.git
% cd aws-iam-access-analyzer-kms-blog
% make deploy
```

### Manual deployment
Alternatively, you can deploy the solution step by step by executing the following command line statements.

#### Clone the source code repository to your local enviroment
```bash
% git clone https://github.com/aws-samples/aws-iam-access-analyzer-kms-blog.git
% cd aws-iam-access-analyzer-kms-blog
```

#### Create SNS topic and subscription
```bash
aws sns create-topic --name access-analyzer-kms-keys-findings
```

Please note the `TopicArn` output. We will use it on the next step.

Replace the variables `TOPIC_ARN` with the SNS topic arn returned from the previous command and `EMAIL_ADDRESS` with your email address
```bash
TOPIC_ARN=
EMAIL_ADDRESS=

aws sns subscribe \
    --topic-arn ${TOPIC_ARN} \
    --protocol email \
    --notification-endpoint ${EMAIL_ADDRESS}
```

#### Add permissions to enable EventBridge to publish to SNS topic
Using the `TOPIC_ARN` from the previous call, add the resource-based policy to the SNS topic:
```bash
ACCOUNT_ID=<Enter your AWS account id>
TOPIC_ARN=<Amazon SNS topic ARN>

aws sns set-topic-attributes --topic-arn "${TOPIC_ARN}" \
    --attribute-name Policy \
    --attribute-value "{\"Version\":\"2012-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__default_statement_ID\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":[\"SNS:GetTopicAttributes\",\"SNS:SetTopicAttributes\",\"SNS:AddPermission\",\"SNS:RemovePermission\",\"SNS:DeleteTopic\",\"SNS:Subscribe\",\"SNS:ListSubscriptionsByTopic\",\"SNS:Publish\",\"SNS:Receive\"],\"Resource\":\"${TOPIC_ARN}\",\"Condition\":{\"StringEquals\":{\"AWS:SourceOwner\":\"${ACCOUNT_ID}\"}}}, {\"Sid\":\"PublishEventsToSNSTopic\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"events.amazonaws.com\"},\"Action\":\"sns:Publish\",\"Resource\":\"${TOPIC_ARN}\"}]}"
```

#### Create Lambda execution role  
To create our Lambda function, we need first to create an [execution role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html) that the function will assume:

```bash
aws iam create-role \
    --role-name access-analyzer-kms-function-role \
    --assume-role-policy-document '{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
```

This call returns the execution role ARN which you will need in the step “Create Lambda function”.

Attach the AWS managed policy `AWSLambdaBasicExecutionRole` to the Lambda execution role:

```bash
aws iam attach-role-policy \
    --role-name access-analyzer-kms-function-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

Along with basic Lambda execution permissions for creating CloudWatch log stream and putting log events into the log stream, we need to add specific permissions to allow our function to perform the following actions:
-	Create Access Analyzer (together with permission to create a [service-linked role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-service-linked-role))
-	Work with Access Analyzer API
-	List and describe AWS KMS keys
-	Publish events to an EventBridge bus

Attach the custom permission policy with these permissions to the function execution role. Replace `ACCOUNT_ID` placeholder in the file [lambda-function-access-analyzer-KMS-permissions.json](policies/lambda-function-access-analyzer-KMS-permissions.json):
```bash
aws iam put-role-policy \
    --role-name access-analyzer-kms-function-role \
    --policy-name LambdaAccessAnalyzerKMSExecutionRole \
    --policy-document file://policies/lambda-function-access-analyzer-KMS-permissions.json
```

#### Create Lambda function
Now you can create the lambda funtion.
Replace `ROLE_ARN` with the ARN from `aws iam create-role` call:
```bash
ROLE_ARN=

aws lambda create-function \
    --function-name access-analyzer-kms-function \
    --runtime python3.8 \
    --handler access_analyzer_kms_function.lambda_handler \
    --role ${ROLE_ARN} \
    --timeout 120 \
    --zip-file fileb://functions/access_analyzer_kms_function.zip
```

#### Create an EventBridge rule and wire it to the Lambda function
The last step in the deployment of the Access Analyzer-based public access detection solution is to set up an EventBridge rule which will trigger the Lambda function.
We want to trigger the Access Analyzer KMS key scan on any changes in key policy or on creation of a key grant.
The two API operations responsible for this are `PutKeyPolicy` and `CreateGrant`.

To create a rule that triggers on those actions we should capture those specific AWS KMS API calls in EventBridge via AWS CloudTrail using the following event pattern:
```json
{
    "source": [
        "aws.kms"
    ],
    "detail-type": [
        "AWS API Call via CloudTrail"
    ],
    "detail": {
        "eventSource": [
            "kms.amazonaws.com"
    ],
    "eventName": [
        "PutKeyPolicy",
        "CreateGrant"
    ]
    }
}
```

First, create the EventBrige rule:
```bash
aws events put-rule \
    --name kms-key-access-changes \
    --event-pattern "{\"source\": [\"aws.kms\"],\"detail-type\": [\"AWS API Call via CloudTrail\"],\"detail\": {\"eventSource\": [\"kms.amazonaws.com\"],\"eventName\": [\"PutKeyPolicy\",\"CreateGrant\"]}}" 
```

To allow the EventBridge rule to invoke our Lambda function we must add the resource-based policy to the function. Replace `RULE_ARN` with the ARN returned from the `aws events put-rule` call:
```bash
RULE_ARN=

aws lambda add-permission \
    --function-name access-analyzer-kms-function \
    --statement-id EventBridgeRuleLambdaPermission \
    --action 'lambda:InvokeFunction' \
    --principal events.amazonaws.com \
    --source-arn ${RULE_ARN}
```

Now, with the rule and permissions in place, we need to link the rule and the function (target). Replace `FUNCTION_ARN` with the Lambda function ARN from the `aws lambda create-function` call:
```bash
FUNCTION_ARN=

aws events put-targets \
    --rule kms-key-access-changes \
    --targets "Id"="1","Arn"="${FUNCTION_ARN}"
```

#### Create an EventBridge rule to publish findings to Amazon SNS topic
In this section we create a second EventBridge rule, which will publish the findings from the Lambda function to our Amazon SNS topic (`TOPIC_ARN`)

We use the following event pattern for the EventBridge rule to invoke it for each findings event sent by the Lambda function:
```json
{
    "source": [
      "access-analyzer-kms-function"
    ],
    "detail-type": [
      "Access Analyzer KMS Findings"
    ]
}
```

First, create the EventBridge rule:
```bash
aws events put-rule \
    --name kms-key-access-findings \
    --event-pattern "{\"source\": [\"access-analyzer-kms-function\"],\"detail-type\": [\"Access Analyzer KMS Findings\"]}" 
```

Finally, set the Amazon SNS topic as a target for the EventBrige rule:
```bash
aws events put-targets \
    --rule kms-key-access-findings \
    --targets "Id"="1","Arn"="${TOPIC_ARN}"
```

## Test detection of public access for AWS KMS key polices
Create a KMS key:
```bash
aws kms create-key \
    --description "Access Analyzer KMS customer key scan test"
```

Please note `KeyId` - we will need it on the next step.

Make the key public by adding `"*"` to the allowed principal list. Replace `KEY_ID` with the value returned by `aws kms create-key` call. Replace `ACCOUNT_ID` with the current AWS account id:
```bash
KEY_ID=
ACCOUNT_ID=

aws kms put-key-policy \
    --key-id ${KEY_ID} \
    --policy-name default \
    --policy "{\"Version\": \"2012-10-17\",\"Id\": \"key-default-policy\",\"Statement\": [{\"Sid\": \"Enable IAM User Permissions\",\"Effect\": \"Allow\",\"Principal\": {\"AWS\": [\"arn:aws:iam::${ACCOUNT_ID}:root\",\"*\"]},\"Action\": \"kms:*\",\"Resource\": \"*\"}]}"
```

Check your email. You will receive a notification from the Lambda function about public access to your KMS key.

Set the policy to private again:
```bash
aws kms put-key-policy \
    --key-id ${KEY_ID} \
    --policy-name default \
    --policy "{\"Version\": \"2012-10-17\",\"Id\": \"key-default-policy\",\"Statement\": [{\"Sid\": \"Enable IAM User Permissions\",\"Effect\": \"Allow\",\"Principal\": {\"AWS\": [\"arn:aws:iam::${ACCOUNT_ID}:root\"]},\"Action\": \"kms:*\",\"Resource\": \"*\"}]}"
```

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0