# RDS Logs Archiver

A simple Lambda function for archiving RDS logs to a S3 bucket.

See the [blog post](https://engineering.citymapper.com/archiving-rds-logs-automatically.html) for more details.

## Running it locally

The Lambda function can be executed locally by running it with some command-line arguments.

You will need to have a Python environment with boto3 installed, e.g.

```sh
virtualenv env
. env/bin/activate
pip install boto3
```

Then you can run the function and see the necessary command-line arguments,

```sh
python rds_logs_archiver.py
```

(It isn't necessary to include boto3 when running as a Lambda function as it is available as part of that environment.)

## Deploying

The easiest way to deploy this is to use the CloudFormation template.

If you want to deploy using other mechanisms, e.g. Terraform, it's best to look at the CloudFormation and translate it from there. It contains all the configuration and security permissions necessary.

To deploy using the CloudFormation template,

1. Create the S3 bucket to archive the log files to. You may want to add a retention policy to purge logs after a period of time.

2. Create a ZIP file with `rds_logs_archiver.py` in it. It must be named `rds_logs_archiver.py` and must live in the root of the ZIP file. If it isn't, Lambda won't be able to find the code and run it.

3. Upload the ZIP file to an S3 bucket so Lambda can use it. It can be the same as the bucket the log files will be archived to.

4. Create the stack in CloudFormation using the template. Change the parameters as necessary to reflect your setup, e.g. database identifier and bucket to archive logs to.

The Lambda function should execute within the next 10 minutes, and every 10 minutes after that.

If you want, you can manually trigger an execution by navigating to the function in the AWS console, and sending a test event with an empty payload (i.e. `{}`).
