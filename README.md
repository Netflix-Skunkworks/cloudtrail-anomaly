# CloudTrail Application Anomaly Detection

This project is a simple CloudTrail based anomaly detection for use in AWS.  It keeps track of all API actions a principal calls (that are tracked by CloudTrail) for a N day period and alerts on new API calls after the N day period.

## Disclaimer

We are releasing this as a proof-of-concept with no intent to provide support. Please use it as a starting point for your own work in this space.

## Getting Started

To get started you will need the following resources created in your AWS environment:

- DynamoDB Table to keep API actions
- Athena Tables (1 per account you want to track CloudTrail anomalies for roles)
- SNS Topic to alert to when an anomaly is detected

### Prerequisites

You must centralize CloudTrail to a single S3 bucket for Athena to query. The code is configured to query for any API calls from the last `1` hour. This means you should run updates at least this frequently otherwise you may miss events that happened since last update but outside of the `1` hour window. You can adjust these parameters as it makes sense in your environment, but generally more frequent updates are better because you get quicker notifications.

### Create DynamoDB Table

The DynamoDB table should be created in the account and region you wish to run this tool in.  

Create a table with a `Partition Key` called `RoleId` and a `Sort Key` called `Action`. You must also enable TTL for a field called `TTL`.

We recommend allowing AWS to autoscale your DynamoDB and you most likely will need to play around with read and write capacity as your roll this out.

### Create SNS Topic

Create a SNS topic in the account and region you wish to run this tool in.  It can also be in another account, but you will need to setup a cross account SNS resource policy if you do.  Note this ARN of the SNS topic for use in creating your IAM role later.

### IAM Roles Creation

Create the following roles in your accounts:

- `ctanomalyInstanceProfile` in the account you wish to run this tool from
- `CT_OrgsRole` in your AWS Organizations parent account
- `CT_IamReadOnly` in every account you wish to run anomaly detection against with CloudTrail
- `CT_AthenaRole` in the account where you have CloudTrail centralized to a S3 bucket

#### CloudTrail Anomaly Application Role

This is the role that the code will run as from any AWS account you choose.  This can be a completely new AWS account (recommended), the account you centralize CloudTrail to, or any other AWS account in your enterprise.

Role Name: `ctanomalyInstanceProfile`

Inline Policy: 

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sts:AssumeRole"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:iam::ORGS_ACCOUNT_NUMBER:role/CT_OrgsRole",
                "arn:aws:iam::*:role/CT_IamReadOnly",
                "arn:aws:iam::ACCOUNT_WHERE_CLOUDTRAILBUCKET_IS:role/CT_AthenaRole"
            ]
        },
        {
            "Action": [
                "dynamodb:PutItem",
                "dynamodb:Query",
                "dynamodb:UpdateItem"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Action": [
                "sns:Publish"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:sns:REGION:ACCOUNT_NUMBER:cloudtrail_anomaly"
        }
    ]
}
```

Trust Policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

#### Organization Role

If you want to be automatically look at roles in all of your AWS Organization accounts, you must provide a role with a trust relationship to the CloudTrail Anomaly Application Role above.

Role Name: `CT_OrgsRole`

Inline Policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "organizations:ListAccounts"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}
```

Trust Policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_NUMBER:role/ctanomalyInstanceProfile"
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
```

#### IAM Read Only Role

The IAM read only role lists all the roles in each AWS account to know which roles to track in CloudTrail.

Role Name: `CT_IamReadOnly`

Inline Policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:ListRoles",
            "Resource": "*"
        }
    ]
}
```

Trust Policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_NUMBER:role/ctanomalyInstanceProfile"
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
```

#### Athena Role

This role is used to make the Athena queries.  It needs access to the Athena service, Glue service, and access to the S3 bucket where CloudTrail is stored.

Role Name: `CT_AthenaRole`

Easiest way to get started is to attach the `AmazonAthenaFullAccess` managed policy.

`arn:aws:iam::aws:policy/AmazonAthenaFullAccess`

In addition to this, you will need access to the CloudTrail bucket.

Inline Policy: 

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::CLOUDTRAIL_BUCKET_HERE",
                "arn:aws:s3:::CLOUDTRAIL_BUCKET_HERE/*"
            ]
        }
    ]
}
```

Trust Policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_NUMBER:role/ctanomalyInstanceProfile"
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
```

### Athena Table Creation

To create the necessary Athena tables run the following command:

`ct_anomaly --verbosity INFO --config config.yml setup athena`

alternatively you can choose to create the Athena tables for only a subset of your accounts with the following command:

`ct_anomaly --verbosity INFO --config config.yml setup athena --accounts 1234567890,0987654321`

where your account numbers are comma delimited.

### Config File Example

```yaml
roleAction:
  dayThreshold: 90
  # IgnoredActionsNotify: 
  #   - sts.amazonaws.com:GetCallerIdentity
aws:
  region: us-west-2
  dynamoTableName: cloudtrail_anomaly
  snsTopicArn: arn:aws:sns:us-west-2:1234567890:cloudtrail_anomaly
  organizations:
    accountId: 1234567890
    roleName: CT_OrgsRole
  iam:
    roleName: CT_IamReadOnly
  athena:
    database: default
    accountId: 0987654321
    roleName: CT_AthenaRole
    bucket: aws-athena-query-results-0987654321-us-west-2
    prefix: cloudtrailbucket
    cloudtrailBucket: cloudtrailbucket
```

## Detecting Anomalies

To detect anomalies for roles in all accounts, run the following command:

`ct_anomaly --verbosity INFO --config config.yml detect anomaly`

To detect anomalies for roles in a subset of accounts, run the following command:

`ct_anomaly --verbosity INFO --config config.yml detect anomaly --accounts 1234567890,0987654321`

where your account numbers are comma delimited.

### Example Output

```
ct_anomaly --verbosity INFO --config config.yml detect anomaly
Getting accounts from organizations
Received 25 accounts from Organizations
Getting roles from 1234567890
Running Athena Query for AWSServiceRoleForOrganizations in 1234567890
Running Athena Query for AWSServiceRoleForSupport in 1234567890
Running Athena Query for AWSServiceRoleForTrustedAdvisor in 1234567890
Running Athena Query for CT_AthenaRole in 1234567890
Newly seen action: CT_AthenaRole - athena.amazonaws.com:GetQueryExecution in 1234567890
Running Athena Query for CT_IamReadOnly in 1234567890
Newly seen action: CT_IamReadOnly - iam.amazonaws.com:ListRoles in 1234567890
Running Athena Query for demoLambda in 1234567890
Running Athena Query for demoRole in 1234567890
Running Athena Query for trailblazer in 1234567890
...
```