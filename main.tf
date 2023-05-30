provider "aws" {
  region = var.aws_region
}
resource "aws_iam_role" "lambda_role" {
  name = "lambda_function_role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "lambda_function_policy"
  description = "Permissions for the Lambda function"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::Data-storage-bucket",
        "arn:aws:s3:::Data-storage-bucket/*"
      ]
    },
    // Add any additional permissions or policies here as needed
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

// Create an S3 bucket for storing uploaded files
resource "aws_s3_bucket" "sftp_bucket" {
  bucket = "Data-storage-bucket"
  acl    = "private"

  // Add any additional S3 bucket configurations as needed
}

// Create a Transfer for SFTP server
resource "aws_transfer_server" "sftp_server" {
  identity_provider_type = "SERVICE_MANAGED"
  endpoint_type          = "PUBLIC"

  tags = {
    Name = "sftp-server"
  }
}

// Define the VPC and subnets for the SFTP server
resource "aws_transfer_ssh_key" "sftp_key" {
  server_id = aws_transfer_server.sftp_server.id
  ssh_public_key_body = <<EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC30...
EOF
}

resource "aws_transfer_user" "sftp_user" {
  server_id       = aws_transfer_server.sftp_server.id
  user_name       = "sftpuser"
  home_directory = "/home/sftpuser"
  role            = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
  ssh_public_key_body = aws_transfer_ssh_key.sftp_key.ssh_public_key_body
}

// Create security groups for the SFTP server
resource "aws_security_group" "sftp_security_group" {
  name        = "sftp_security_group"
  description = "Security group for SFTP server"

  // Add any additional security group configurations as needed
}

resource "aws_security_group_rule" "sftp_inbound_rule" {
  security_group_id = aws_security_group.sftp_security_group.id
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "sftp_outbound_rule" {
  security_group_id = aws_security_group.sftp_security_group.id
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
}

// Associate security groups with the SFTP server
resource "aws_transfer_server" "sftp_server" {
  ...
  security_group_ids = [aws_security_group.sftp_security_group.id]
}

// Enable integration with the S3 bucket
resource "aws_transfer_server_user" "sftp_user" {
  server_id = aws_transfer_server.sftp_server.id
  user_name = aws_transfer_user.sftp_user.user_name

  home_directory_type = "LOGICAL"
  home_directory      = "Data-storage-bucket"
}
// Create a Lambda function to process uploaded files
resource "aws_lambda_function" "process_files_lambda" {
  filename         = "lambda_function.zip"  // Path to your Lambda function code
  function_name    = "process_files_lambda"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  runtime          = "nodejs14.x"
  timeout          = 300  // Set the desired timeout value
  memory_size      = 512  // Set the desired memory size value

  // Add any additional Lambda function configurations as needed
}

// Create an S3 bucket event trigger for the Lambda function
resource "aws_s3_bucket_notification" "s3_bucket_notification" {
  bucket = Data-storage-bucket.sftp_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.process_files_lambda.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".csv"  // Set the desired file suffix
  }
}

// Create a CloudWatch Events rule
resource "aws_cloudwatch_event_rule" "missing_data_rule" {
  name        = "missing_data_rule"
  description = "Rule to trigger Lambda function for missing data check"
  schedule_expression = "rate(1 day)"  // Set the desired schedule for the data check

  // Add any additional CloudWatch Events rule configurations as needed
}

// Add a target to the CloudWatch Events rule to trigger the Lambda function
resource "aws_cloudwatch_event_target" "missing_data_target" {
  rule      = aws_cloudwatch_event_rule.missing_data_rule.name
  target_id = "missing_data_target"
  arn       = aws_lambda_function.process_files_lambda.arn
}

// Update the Lambda function to check for missing data and send alerts
resource "aws_lambda_function" "process_files_lambda" {
  ...

  // Add the following environment variable to pass the S3 bucket name
  environment {
    variables = {
      Data-storage-bucket= aws_s3_bucket.sftp_bucket.id
    }
  }

  // Add the following code block to the existing Lambda function code
  // This code assumes you are using Node.js for the Lambda function implementation
  // Replace it with your preferred programming language if using a different one
  // This code queries the S3 bucket for missing files and sends an alert if any agencies' data is missing
  // You can modify and expand this code based on your specific requirements
  // Ensure you have the necessary packages installed, such as the AWS SDK for your chosen programming language
  // This example assumes you have the AWS SDK for JavaScript installed
  // Install it using "npm install aws-sdk"
  // The following code snippet is an example and may need modifications based on your specific use case

  // Install the AWS SDK for JavaScript by running "npm install aws-sdk"
  const AWS = require('aws-sdk');
  const s3 = new AWS.S3();

  exports.handler = async (event, context) => {
    try {
      const s3BucketName = process.env.S3_BUCKET_NAME;

      // Retrieve a list of agencies from a data source (e.g., database, API)
      const agencies = ['agency1', 'agency2', 'agency3'];

      for (const agency of agencies) {
        const key = `${agency}.csv`;
        const params = {
          Bucket: Data-storage-bucket,
          Key: key,
        };

        try {
          // Check if the file exists in the S3 bucket
          await s3.headObject(params).promise();
        } catch (error) {
          // File doesn't exist, send an alert
          console.log(`Missing data for agency: ${agency}`);
          // Implement the code to send an alert (e.g., via email, SNS, etc.)
        }
      }
    } catch (error) {
      console.log('Error occurred:', error);
      // Handle the error as per your requirements
    }
  };
}
// Create a KMS key for encrypting the parameter value
resource "aws_kms_key" "parameter_key" {
  description             = "KMS key for encrypting SFTP user credentials"
  enable_key_rotation     = true

  // Add any additional KMS key configurations as needed
}

// Create a SecureString parameter in AWS Systems Manager Parameter Store
resource "aws_ssm_parameter" "sftp_user_credentials" {
  name        = "/sftp/user/credentials"
  description = "SFTP user credentials"
  type        = "SecureString"
  value       = "sftp_username:sftp_password"  // Replace with actual credentials
  key_id      = aws_kms_key.parameter_key.key_id

  
}

// Grant necessary permissions to access the parameter
resource "aws_kms_key_grant" "parameter_key_grant" {
  key_id            = aws_kms_key.parameter_key.key_id
  grantee_principal = "arn:aws:iam::us-east-1:123456789012"  // Replace with the ARN of the role requiring access to the parameter
  operations        = ["Decrypt"]
  constraint_actions = ["GetParameter"]
  grant_creation_tokens = ["*"]
}

// Create an SNS topic for sending alerts
resource "aws_sns_topic" "missing_data_topic" {
  name = "missing_data_topic"

  // Add any additional SNS topic configurations as needed
}

// Create a subscription for the desired notification channel (e.g., email)
resource "aws_sns_topic_subscription" "notification_subscription" {
  topic_arn = aws_sns_topic.missing_data_topic.arn
  protocol  = "email"
  endpoint  = "@gmail.com"  // Replace with the appropriate email address

 
}

// Update the Lambda function to publish a message to the SNS topic in case of missing data
resource "aws_lambda_function" "process_files_lambda" {

  
  const AWS = require('aws-sdk');
  const sns = new AWS.SNS();

  exports.handler = async (event, context) => {
    try {
      const s3BucketName = process.env.Data-storage-bucket;
      const snsTopicArn = "arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:missing_data_topic";  // Replace with the ARN of the SNS topic

      // Retrieve a list of agencies from a data source (e.g., database, API)
      const agencies = ['agency1', 'agency2', 'agency3'];
      const missingAgencies = [];

      for (const agency of agencies) {
        const key = `${agency}.csv`;
        const params = {
          Bucket: Data-storage-bucket,
          Key: key,
        };

        try {
          // Check if the file exists in the S3 bucket
          await s3.headObject(params).promise();
        } catch (error) {
          // File doesn't exist, add agency to the missingAgencies array
          missingAgencies.push(agency);
        }
      }

      if (missingAgencies.length > 0) {
        // Publish a message to the SNS topic
        const message = `Missing data for agencies: ${missingAgencies.join(", ")}`;
        const publishParams = {
          TopicArn: snsTopicArn,
          Message: message,
        };

        await sns.publish(publishParams).promise();
      }
    } catch (error) {
      console.log('Error occurred:', error);
      // Handle the error as per your requirements
    }
  };
}



