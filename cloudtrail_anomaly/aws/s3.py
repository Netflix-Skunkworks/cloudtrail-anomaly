from cloudtrail_anomaly import log


def read_data_from_s3(bucket, key, cloudaux=None):
    """Read the s3 file"""
    log.debug('Downloading and reading S3 file s3://{}/{}'.format(bucket, key))
    s3_response_object = cloudaux.call(
        's3.client.get_object',
        Bucket=bucket,
        Key=key)
    
    data = s3_response_object['Body'].read()

    return data.decode('utf-8').replace('"', '').split('\n')
