import argparse
import logging
import os
import sys

import boto3
import botocore.awsrequest
from botocore.exceptions import ClientError


MAX_LOG_FILES_PER_EXECUTION = 10
LAST_WRITTEN_KEY = 'last_written.txt'


logger = logging.getLogger()


def archive_rds_logs_lambda_handler(event, context):
    # Lambda sets up logging, but the default level does not include INFO
    logger.setLevel(logging.INFO)

    db_identifier = os.environ['db_identifier']
    if not db_identifier:
        raise ValueError('the environment variable db_identifier was not set')
    bucket_name = os.environ['bucket_name']
    if not bucket_name:
        raise ValueError('the environment variable bucket_name was not set')
    bucket_prefix = os.environ.get('bucket_prefix', '')

    more_logs = archive_rds_logs(db_identifier, bucket_name, bucket_prefix)

    if more_logs:
        reinvoke_self(context)


def archive_rds_logs(db_identifier, bucket_name, bucket_prefix):
    logger.info('Archiving RDS logs for "%s" to s3://%s/%s', db_identifier, bucket_name, bucket_prefix)

    s3 = boto3.client('s3', region_name='eu-west-1')
    rds = boto3.client('rds', region_name='eu-west-1')

    last_written_in_bucket = get_last_written_in_bucket(s3, bucket_name, bucket_prefix)
    logger.info('Last written log in bucket - %s', last_written_in_bucket)

    log_metadata_dicts, more_logs = get_rds_log_metadata_dicts(rds, db_identifier, last_written_in_bucket)

    for log_metadata_dict in log_metadata_dicts:
        log_filename = log_metadata_dict["filename"]
        log_size_bytes = log_metadata_dict["size_bytes"]
        log_last_written = log_metadata_dict["last_written"]

        logger.info('Archiving %s (%d bytes) to S3', log_filename, log_size_bytes)
        log_size_bytes_archived = archive_rds_log_file(
            rds, db_identifier, log_filename, log_size_bytes, s3, bucket_name, bucket_prefix,
        )

        set_last_written_in_bucket(s3, bucket_name, bucket_prefix, log_last_written)
        logger.info('Archived %s (%d bytes)', log_filename, log_size_bytes_archived)

    if more_logs:
        logger.info('there are more logs available to archive - call this again')

    return more_logs


def get_last_written_in_bucket(s3, bucket_name, bucket_prefix):
    key = get_last_written_bucket_key(bucket_prefix)

    try:
        response = s3.get_object(Bucket=bucket_name, Key=key)
    except ClientError as e:
        error = e.response.get('Error', {})
        logger.info(error)
        if error.get('Code') == 'NoSuchKey':
            return None

        raise

    timestamp = response['Body'].read().strip()
    timestamp = int(timestamp)

    return timestamp


def set_last_written_in_bucket(s3, bucket_name, bucket_prefix, last_written):
    key = get_last_written_bucket_key(bucket_prefix)
    s3.put_object(Bucket=bucket_name, Key=key, Body=str(last_written))


def get_last_written_bucket_key(bucket_prefix):
    key_parts = []
    if bucket_prefix:
        key_parts.append(bucket_prefix)
    key_parts.append(LAST_WRITTEN_KEY)
    key = '/'.join(key_parts)

    return key


def get_rds_log_metadata_dicts(rds, db_identifier, last_written):
    """
    This will return logs inclusive of those that match the last_written timestamp. Therefore on each execution, we will
    re-retrieve the log that was last uploaded in the last execution, even if nothing has changed.
    """
    logger.info(
        'Retrieving log filenames, from last written %s, up to %d logs', last_written, MAX_LOG_FILES_PER_EXECUTION,
    )

    # we can't use max records to return only the records we want because the API returns the latest logs first, where
    # we want the oldest logs first, so later executions can process the newer logs. RDS only stores up to 7 days'
    # worth of logs, so this shouldn't be a big problem
    all_log_metadata_dicts = []
    marker = None
    while True:
        args = dict(DBInstanceIdentifier=db_identifier, FileLastWritten=0)
        if last_written is not None:
            args['FileLastWritten'] = last_written
        if marker is not None:
            args['Marker'] = marker

        response_data = rds.describe_db_log_files(**args)
        log_metadata_dicts, marker = parse_log_metadata_dicts_from_response(response_data)

        all_log_metadata_dicts.extend(log_metadata_dicts)
        if marker is None:
            break

    all_log_metadata_dicts.sort(key=lambda x: x["last_written"])
    more_logs = len(all_log_metadata_dicts) > MAX_LOG_FILES_PER_EXECUTION
    log_metadata_dicts_within_max = all_log_metadata_dicts[:MAX_LOG_FILES_PER_EXECUTION]
    logger.info('Found %d log files, more_logs = %s', len(log_metadata_dicts_within_max), more_logs)

    return log_metadata_dicts_within_max, more_logs


def parse_log_metadata_dicts_from_response(response_data):
    file_dicts = response_data['DescribeDBLogFiles']

    log_metadata_dicts = [
        dict(filename=file_dict['LogFileName'], size_bytes=file_dict['Size'], last_written=file_dict['LastWritten'])
        for file_dict in file_dicts
    ]
    marker = response_data.get('Marker')

    return log_metadata_dicts, marker


def archive_rds_log_file(rds, db_identifier, log_filename, log_size_bytes, s3, bucket_name, bucket_prefix):
    """
    Uses RDS API, but it is not implemented in boto3, hence the private boto3 API access
    https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html#DownloadCompleteDBLogFile

    NOTE: can use the download_db_log_file_portion API instead, but would need multiple calls as it is
    a line-based API and only returns 1MB max per call.
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.download_db_log_file_portion
    """

    path = '/v13/downloadCompleteLogFile/{}/{}'.format(db_identifier, log_filename)
    url = '{}{}'.format(rds.meta.endpoint_url, path)

    request = botocore.awsrequest.AWSRequest(
        method='GET',
        url=url,
        data=None,
        headers={'User-Agent': rds.meta.config.user_agent},
        stream_output=True,
    )
    request.context.update({'client_config': rds.meta.config})
    rds.meta.events.emit('request-created.rds', request=request)
    response = rds._endpoint.http_session.send(request.prepare())

    key = log_filename
    if bucket_prefix is not None:
        key = '{}/{}'.format(bucket_prefix, key)

    bytes_read_count_accumulator = Accumulator()

    try:
        s3.upload_fileobj(
            response.raw,
            Bucket=bucket_name,
            Key=key,
            Callback=bytes_read_count_accumulator.add,
        )
    finally:
        response.raw.close()

    bytes_read_count = bytes_read_count_accumulator.total
    # the logs may have further entries between the calls, so we just want to make sure we're getting at least the
    # number of bytes promised in the Describe call
    if bytes_read_count < log_size_bytes:
        raise Exception('Expected at least {} bytes, got {} bytes instead'.format(log_size_bytes, bytes_read_count))

    return bytes_read_count


class Accumulator(object):
    def __init__(self, start=0):
        self.total = start

    def add(self, value):
        self.total += value


def reinvoke_self(context):
    lambda_client = boto3.client('lambda')
    lambda_client.invoke(
        FunctionName=context.function_name,
        InvocationType='Event',
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('db_identifier', help='identifier of database in RDS')
    parser.add_argument('bucket_name', help='name of bucket to archive logs into')
    parser.add_argument('bucket_prefix', help='prefix to use for log files in bucket')
    args = parser.parse_args()

    archive_rds_logs(args.db_identifier, args.bucket_name, args.bucket_prefix)

    return 0


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(asctime)s (%(levelname)s) %(message)s")
    sys.exit(main())
