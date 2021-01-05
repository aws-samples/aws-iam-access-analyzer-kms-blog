# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import uuid
import json
import datetime
import time
import os

# class JSONEncoder
class DateTimeEncoder(json.JSONEncoder):
        #Override the default method
        def default(self, obj):
            if isinstance(obj, (datetime.date, datetime.datetime)):
                return str(obj.isoformat())


MAX_LIST_ANALYZED_RESOURSES_ATTEMPTS = 10
MAX_LIST_ANALYZED_RESOURCES_RESULTS = 100
RESOURCE_TYPE_KMS = "AWS::KMS::Key"
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:906545278380:access-analyzer-kms-keys-findings")
analyzer_arn = ""
kms_client = boto3.client("kms")
aa_client = boto3.client('accessanalyzer')

snsTopic = boto3.resource('sns').Topic(SNS_TOPIC_ARN)
accountId = boto3.client('sts').get_caller_identity()["Account"]

# get or create access analyzer
def get_analyzer_arn():
    aa_arn = ""

    try:
        # get all active analyzers for the given account
        active_analyzers = [a for a in aa_client.list_analyzers(type="ACCOUNT").get("analyzers") if a["status"] == "ACTIVE"]
        
        if active_analyzers:
            # take the first active analyzer if there are any active analyzer
            aa_arn = active_analyzers[0]["arn"]
        else:
            # try to create a new analyzer if there is no analyzer already created for the account
            aa_arn = aa_client.create_analyzer(
                analyzerName="AccessAnalyzer-" + str(uuid.uuid1()),
                type="ACCOUNT").get("arn")

    except Exception as e:
        print(f"Exception during get analyzer: {str(e)}")

    return aa_arn

# get all KMS keys in the account in the region
def get_customer_keys_arns():
    customer_keys_arns = []
    marker = ""

    try:
        print("Enumerating KMS customer keys")
        while True:
            # list all KMS keys in the account and region
            if marker:
                res = kms_client.list_keys(Limit=100, Marker=marker)
            else: 
                res = kms_client.list_keys(Limit=100)

            # get the KeyManager (AWS or Customer) for each returned key
            for k in res["Keys"]:
                k_data = kms_client.describe_key(KeyId=k["KeyId"]).get("KeyMetadata")
                # take only Customer key (where KeyManager not AWS)
                if k_data['KeyManager'] not in "AWS":
                    customer_keys_arns.append(k_data["Arn"])                

            marker = res.get("NextMarker")
            if not marker:
                break
    except Exception as e:
        print(f"Exception during KMS list and describe keys: {e}")

    print(f"Found customer keys:{json.dumps(customer_keys_arns, indent=2)}")
    return customer_keys_arns


# scan customer keys using access analyser
def scan_kms_customer_keys(aa_arn, customer_keys_arns):    
    findings = []   
    resource_scan = {}

    print(f"AccessAnalyzer:{aa_arn}")

    # initiate scan for reources
    for r_arn in customer_keys_arns:
        try:
            res = aa_client.start_resource_scan(
                analyzerArn=aa_arn,
                resourceArn=r_arn
                )
            print(f"Start_resouce_scan for {r_arn}:{res}")

            resource_scan[r_arn] = False
        except Exception as e:
            print(f"Exception in start_resource_scan for {r_arn}:{str(e)}")

    # wait till all resources get analyzed
    nextToken = ""
    for _ in range(MAX_LIST_ANALYZED_RESOURSES_ATTEMPTS):
        try:
            if nextToken:
                res = aa_client.list_analyzed_resources(
                    analyzerArn=aa_arn,
                    maxResults=MAX_LIST_ANALYZED_RESOURCES_RESULTS,
                    nextToken=nextToken,
                    resourceType=RESOURCE_TYPE_KMS
                )
            else:
                res = aa_client.list_analyzed_resources(
                        analyzerArn=aa_arn,
                        maxResults=MAX_LIST_ANALYZED_RESOURCES_RESULTS,
                        resourceType=RESOURCE_TYPE_KMS
                    )
            nextToken = res.get("nextToken")

            for resource in res["analyzedResources"]:
                if resource["resourceArn"] in resource_scan:
                    resource_scan[resource["resourceArn"]] = True

            pending = {r:s for r,s in resource_scan.items() if not s}

            if not pending: # exit if all requested resources are processed
                break
            
            time.sleep(0.5)
        except Exception as e:
            print(f"Exception in list analysed resources loop:{str(e)}")
    else:
        print(f"Max number ({MAX_LIST_ANALYZED_RESOURSES_ATTEMPTS}) of attempts to call list_analyzed_resources reached")
        print(f"The following resources weren't analyzed: {json.dumps(pending, indent=2)}")
        
    # get resource scan result only on analyzed resources
    for r_arn in {r for r,s in resource_scan.items() if s}:
        try:
            print(f"get_analysed_resource: {r_arn}")
            res = aa_client.get_analyzed_resource(
                analyzerArn=aa_arn,
                resourceArn=r_arn)
            print(f"get_analysed_resouce result for {r_arn}:{res}")

            resource = res["resource"]
            if resource.get("isPublic") and resource.get("status") in "ACTIVE":
                print(f"Found public KMS customer key: {r_arn}:{resource}")
                findings.append(resource)

        except Exception as e:
            print(f"Exception in get_analyzed_resource for {r_arn}:{str(e)}")

    return findings


def lambda_handler(event, context):

    print(f"Run AccessAnalyzer on all AWS KMS keys for the account:{accountId}")

    findings = scan_kms_customer_keys(get_analyzer_arn(), get_customer_keys_arns())

    # publish findings to a SNS topic
    if bool(findings):
        snsTopic.publish(
            Message=json.dumps(findings, indent=2, cls=DateTimeEncoder),
            Subject="Public access found for AWS KMS customer keys"
            ) 

    print(f"AccessAnalyzer AWS KMS check completed: {json.dumps(findings, cls=DateTimeEncoder)}")