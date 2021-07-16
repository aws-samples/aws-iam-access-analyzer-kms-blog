# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#SHELL := /bin/sh
PY_VERSION := 3.8

export PYTHONUNBUFFERED := 1

SRC_DIR := functions
SAM_DIR := .aws-sam
TEMPLATE_DIR := .

# Region for deployment
AWS_DEPLOY_REGION ?= us-east-1
# Region for publishing
AWS_PUBLISH_REGION ?= us-east-1

# Stack name used when deploying the app for manual testing
APP_STACK_NAME ?= kms-access-analyzer

PYTHON := $(shell /usr/bin/which python$(PY_VERSION))

.DEFAULT_GOAL := build

zip:
	cd ./functions/access-analyzer-kms && zip access_analyzer_kms_function.zip access_analyzer_kms_function.py && mv access_analyzer_kms_function.zip ../ && cd ../..
	
compile: zip
	pipenv run sam build -p -t $(TEMPLATE_DIR)/template.yaml -m $(SRC_DIR)/requirements.txt --debug

build: compile

deploy: compile
	pipenv run sam deploy --template-file $(SAM_DIR)/build/template.yaml \
						  --stack-name $(APP_STACK_NAME) \
						  --capabilities CAPABILITY_IAM \
						  --region $(AWS_DEPLOY_REGION) \
						  --confirm-changeset \
						  --guided
