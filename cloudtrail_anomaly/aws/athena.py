import re
import time

from cloudtrail_anomaly import log


def query_athena(config, query, cloudaux=None, max_execution=20):
    """Run Athena Query"""
    response = cloudaux.call(
        'athena.client.start_query_execution',
        QueryString=query,
        QueryExecutionContext={
            'Database': config.get('athena', {}).get('database', 'default')
        },
        ResultConfiguration={
            'OutputLocation': 's3://' + config['aws']['athena']['bucket'] + '/' + config.get('aws', {}).get('athena', {}).get('prefix', 'cloudtrail_anomaly')
        }
    )

    execution_id = response['QueryExecutionId']

    state = 'RUNNING'

    # wait 2 mins to run query before moving on
    max_execution_timeout = 120

    while (max_execution > 0 and state in ['RUNNING']):
        max_execution = max_execution - 1
        response = cloudaux.call(
            'athena.client.get_query_execution',
            QueryExecutionId = execution_id
        )

        if 'QueryExecution' in response and \
                'Status' in response['QueryExecution'] and \
                'State' in response['QueryExecution']['Status']:
            state = response['QueryExecution']['Status']['State']
            if state == 'FAILED':
                return False
            elif state == 'SUCCEEDED':
                s3_path = response['QueryExecution']['ResultConfiguration']['OutputLocation']
                filename = re.findall('.*\/(.*)', s3_path)[0]
                return filename
        time.sleep(1)
    return False


def create_table(config, account_number, cloudaux=None, max_execution=20):

    query_string = """CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_{account_number} (
    eventVersion STRING,
    userIdentity STRUCT<
        type: STRING,
        principalId: STRING,
        arn: STRING,
        accountId: STRING,
        invokedBy: STRING,
        accessKeyId: STRING,
        userName: STRING,
        sessionContext: STRUCT<
            attributes: STRUCT<
                mfaAuthenticated: STRING,
                creationDate: STRING>,
            sessionIssuer: STRUCT<
                type: STRING,
                principalId: STRING,
                arn: STRING,
                accountId: STRING,
                userName: STRING>>>,
    eventTime STRING,
    eventSource STRING,
    eventName STRING,
    awsRegion STRING,
    sourceIpAddress STRING,
    userAgent STRING,
    errorCode STRING,
    errorMessage STRING,
    requestParameters STRING,
    responseElements STRING,
    additionalEventData STRING,
    requestId STRING,
    eventId STRING,
    resources ARRAY<STRUCT<
        arn: STRING,
        accountId: STRING,
        type: STRING>>,
    eventType STRING,
    apiVersion STRING,
    readOnly STRING,
    recipientAccountId STRING,
    serviceEventDetails STRING,
    sharedEventID STRING,
    vpcEndpointId STRING
)
COMMENT 'CloudTrail table for {ct_bucket}'
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://{ct_bucket}/AWSLogs/{account_number}/CloudTrail/'
TBLPROPERTIES ('classification'='cloudtrail');"""

    athena_query = query_string.format(
        account_number=account_number,
        ct_bucket=config.get('aws', {}).get('athena', {}).get('cloudtrailBucket', 'cloudtrailbucket'))
    
    file_name = query_athena(config, athena_query, cloudaux)

    return file_name
