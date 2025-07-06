provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "course-feedback-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = "public-subnet-az1"
  }
}

resource "aws_subnet" "private_az1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Name = "private-subnet-az1"
  }
}

resource "aws_subnet" "private_az2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.3.0/24"
  availability_zone = "us-east-1b"
  tags = {
    Name = "private-subnet-az2"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "course-feedback-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "public-route-table"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat_eip" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat_gw" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public.id
  tags = {
    Name = "course-feedback-nat-gw"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw.id
  }
  tags = {
    Name = "private-route-table"
  }
}

resource "aws_route_table_association" "private_az1" {
  subnet_id      = aws_subnet.private_az1.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_az2" {
  subnet_id      = aws_subnet.private_az2.id
  route_table_id = aws_route_table.private.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.us-east-1.s3"
  route_table_ids = [aws_route_table.private.id]
  tags = {
    Name = "s3-endpoint"
  }
}

resource "aws_vpc_endpoint" "aurora" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.us-east-1.rds"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [aws_subnet.private_az1.id, aws_subnet.private_az2.id]
  security_group_ids = [aws_security_group.aurora_sg.id]
  tags = {
    Name = "aurora-endpoint"
  }
}

resource "aws_security_group" "aurora_sg" {
  vpc_id = aws_vpc.main.id
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.lambda_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "aurora-sg"
  }
}

resource "aws_security_group" "lambda_sg" {
  vpc_id = aws_vpc.main.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "lambda-sg"
  }
}

resource "aws_elastic_beanstalk_application" "app" {
  name        = "course-feedback-app"
  description = "Application for course feedback"
}

# Elastic Beanstalk Logging Configuration (remove LogStreaming)
resource "aws_elastic_beanstalk_environment" "env" {
  name                = "course-feedback-env"
  application         = aws_elastic_beanstalk_application.app.name
  solution_stack_name = "64bit Amazon Linux 2023 v6.6.0 running Node.js 22"
  wait_for_ready_timeout = "10m"

  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = "LabInstanceProfile"
  }
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "InstanceType"
    value     = "t2.micro"
  }
  setting {
    namespace = "aws:autoscaling:asg"
    name      = "MinSize"
    value     = "1"
  }
  setting {
    namespace = "aws:autoscaling:asg"
    name      = "MaxSize"
    value     = "4"
  }
  setting {
    namespace = "aws:elb:healthcheck"
    name      = "HealthyThreshold"
    value     = "3"
  }
  setting {
    namespace = "aws:ec2:vpc"
    name      = "VPCId"
    value     = aws_vpc.main.id
  }
  setting {
    namespace = "aws:ec2:vpc"
    name      = "Subnets"
    value     = aws_subnet.private_az1.id
  }
  setting {
    namespace = "aws:ec2:vpc"
    name      = "ELBSubnets"
    value     = aws_subnet.public.id
  }
  setting {
    namespace = "aws:elasticbeanstalk:monitoring"
    name      = "Automatically Terminate Unhealthy Instances"
    value     = "true"
  }
  setting {
    namespace = "aws:elb:loadbalancer"
    name      = "CrossZone"
    value     = "true"
  }
}

# S3 Bucket (from Step 6)
resource "aws_s3_bucket" "feedback_bucket" {
  bucket = "course-feedback-bucket"
  acl    = "private"
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  tags = {
    Name = "course-feedback-bucket"
  }
}

# Secrets Manager for RDS
resource "aws_secretsmanager_secret" "rds_secret" {
  name = "rds-secret-v1"
}

resource "aws_secretsmanager_secret_version" "rds_secret_version" {
  secret_id     = aws_secretsmanager_secret.rds_secret.id
  secret_string = jsonencode({
    username = "admin"
    password = "Test123456"  # Replace with a secure password or use a variable
  })
}

resource "aws_db_instance" "mysql_instance" {
  identifier             = "course-feedback-rds"
  engine                 = "mysql"
  engine_version         = "8.0.35"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = jsondecode(aws_secretsmanager_secret_version.rds_secret_version.secret_string)["username"]
  password               = jsondecode(aws_secretsmanager_secret_version.rds_secret_version.secret_string)["password"]
  db_name                = "feedback_db"
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.aurora_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
  publicly_accessible    = false
  multi_az               = false
  storage_encrypted      = true  # Enable encryption
}

resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "rds-subnet-group"
  subnet_ids = [aws_subnet.private_az1.id, aws_subnet.private_az2.id]
}

# Lambda Function (Updated for RDS and Cognito)
resource "aws_lambda_function" "feedback_processor" {
  filename      = "lambda.zip"  # Update with new code
  function_name = "feedback_processor"
  role          = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/LabRole"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.9"
  timeout       = 10
  memory_size   = 128

  vpc_config {
    subnet_ids         = [aws_subnet.private_az1.id, aws_subnet.private_az2.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      RDS_HOST            = aws_db_instance.mysql_instance.address
      RDS_PORT            = 3306
      RDS_DB_NAME         = aws_db_instance.mysql_instance.db_name
      RDS_USERNAME        = jsondecode(aws_secretsmanager_secret_version.rds_secret_version.secret_string)["username"]
      RDS_PASSWORD        = jsondecode(aws_secretsmanager_secret_version.rds_secret_version.secret_string)["password"]
      SNS_TOPIC_ARN       = aws_sns_topic.notification.arn
      BUCKET_NAME         = aws_s3_bucket.feedback_bucket.bucket
      COGNITO_USER_POOL_ID = aws_cognito_user_pool.course_feedback_pool.id
      AUTH_LAMBDA_ARN     = aws_lambda_function.auth_handler.invoke_arn
    }
  }

  depends_on = [
    aws_s3_bucket.feedback_bucket,
    aws_db_instance.mysql_instance,
    aws_secretsmanager_secret_version.rds_secret_version,
    aws_sns_topic.notification,
    aws_cognito_user_pool.course_feedback_pool,
    aws_lambda_function.auth_handler
  ]
}

# SNS Topic (from Step 7)
resource "aws_sns_topic" "notification" {
  name = "course-feedback-notifications"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.notification.arn
  protocol  = "email"
  endpoint  = "ritvik.wuyyuru@gmail.com"  # Replace with your actual email
}

# Data source to get the current AWS account ID
data "aws_caller_identity" "current" {}

# API Gateway (Reuse existing REST API)
resource "aws_api_gateway_rest_api" "feedback_api" {
  name        = "CourseFeedbackAPI"
  description = "API for course feedback platform"
}

resource "aws_api_gateway_resource" "query_resource" {
  rest_api_id = aws_api_gateway_rest_api.feedback_api.id
  parent_id   = aws_api_gateway_rest_api.feedback_api.root_resource_id
  path_part   = "query"
}

resource "aws_api_gateway_method" "query_method" {
  rest_api_id   = aws_api_gateway_rest_api.feedback_api.id
  resource_id   = aws_api_gateway_resource.query_resource.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "query_integration" {
  rest_api_id             = aws_api_gateway_rest_api.feedback_api.id
  resource_id             = aws_api_gateway_resource.query_resource.id
  http_method             = aws_api_gateway_method.query_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.query_processor.invoke_arn
}

# New resources for student submission flow
resource "aws_api_gateway_resource" "submit_resource" {
  rest_api_id = aws_api_gateway_rest_api.feedback_api.id
  parent_id   = aws_api_gateway_rest_api.feedback_api.root_resource_id
  path_part   = "submit"
}

resource "aws_api_gateway_method" "submit_method" {
  rest_api_id   = aws_api_gateway_rest_api.feedback_api.id
  resource_id   = aws_api_gateway_resource.submit_resource.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "submit_integration" {
  rest_api_id             = aws_api_gateway_rest_api.feedback_api.id
  resource_id             = aws_api_gateway_resource.submit_resource.id
  http_method             = aws_api_gateway_method.submit_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.feedback_processor.invoke_arn
}

# New resources for authentication flow
resource "aws_api_gateway_resource" "auth_resource" {
  rest_api_id = aws_api_gateway_rest_api.feedback_api.id
  parent_id   = aws_api_gateway_rest_api.feedback_api.root_resource_id
  path_part   = "auth"
}

resource "aws_api_gateway_method" "auth_method" {
  rest_api_id   = aws_api_gateway_rest_api.feedback_api.id
  resource_id   = aws_api_gateway_resource.auth_resource.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "auth_integration" {
  rest_api_id             = aws_api_gateway_rest_api.feedback_api.id
  resource_id             = aws_api_gateway_resource.auth_resource.id
  http_method             = aws_api_gateway_method.auth_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.auth_handler.invoke_arn
}

resource "aws_api_gateway_deployment" "api_deployment" {
  depends_on  = [
    aws_api_gateway_integration.query_integration,
    aws_api_gateway_integration.submit_integration,
    aws_api_gateway_integration.auth_integration
  ]
  rest_api_id = aws_api_gateway_rest_api.feedback_api.id
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lambda_permission" "api_gateway_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.query_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.feedback_api.execution_arn}/*/*"
}

resource "aws_lambda_permission" "api_gateway_submit_permission" {
  statement_id  = "AllowAPIGatewayInvokeSubmit"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.feedback_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.feedback_api.execution_arn}/*/*"
}

resource "aws_lambda_permission" "api_gateway_auth_permission" {
  statement_id  = "AllowAPIGatewayInvokeAuth"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auth_handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.feedback_api.execution_arn}/*/*"
}

# New Lambda Function for Authentication Handling
resource "aws_lambda_function" "auth_handler" {
  filename      = "auth_handler.zip"  # Create this separately
  function_name = "auth_handler"
  role          = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/LabRole"
  handler       = "auth_handler.lambda_handler"
  runtime       = "python3.9"
  timeout       = 10
  memory_size   = 128

  vpc_config {
    subnet_ids         = [aws_subnet.private_az1.id, aws_subnet.private_az2.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      COGNITO_USER_POOL_ID = aws_cognito_user_pool.course_feedback_pool.id
      COGNITO_CLIENT_ID    = aws_cognito_user_pool_client.course_feedback_client.id
      DYNAMODB_TABLE_NAME  = aws_dynamodb_table.session_store.name
    }
  }

  depends_on = [
    aws_cognito_user_pool.course_feedback_pool,
    aws_dynamodb_table.session_store
  ]
}

# New Lambda Function for Query Processing
resource "aws_lambda_function" "query_processor" {
  filename      = "query_lambda.zip"  # Create this separately
  function_name = "query_processor"
  role          = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/LabRole"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.9"
  timeout       = 30  # Increased for Athena query processing
  memory_size   = 256

  vpc_config {
    subnet_ids         = [aws_subnet.private_az1.id, aws_subnet.private_az2.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      BUCKET_NAME         = aws_s3_bucket.feedback_bucket.bucket
      SNS_TOPIC_ARN       = aws_sns_topic.notification.arn
      COGNITO_USER_POOL_ID = aws_cognito_user_pool.course_feedback_pool.id
      AUTH_LAMBDA_ARN     = aws_lambda_function.auth_handler.invoke_arn
    }
  }

  depends_on = [
    aws_s3_bucket.feedback_bucket,
    aws_sns_topic.notification,
    aws_cognito_user_pool.course_feedback_pool,
    aws_lambda_function.auth_handler
  ]
}

# Athena Database
resource "aws_athena_database" "feedback_db" {
  name   = "feedback_db"
  bucket = aws_s3_bucket.feedback_bucket.bucket
}

# Athena Workgroup
resource "aws_athena_workgroup" "feedback_workgroup" {
  name        = "feedback_workgroup"
  state       = "ENABLED"
  description = "Workgroup for course feedback queries"

  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.feedback_bucket.bucket}/query-results/"
    }
  }
}

# CloudWatch Log Groups for Lambda
resource "aws_cloudwatch_log_group" "feedback_processor_logs" {
  name              = "/aws/lambda/feedback_processor"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "query_processor_logs" {
  name              = "/aws/lambda/query_processor"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "auth_handler_logs" {
  name              = "/aws/lambda/auth_handler"
  retention_in_days = 30
}

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "api_gateway_logs" {
  name              = "/aws/api-gateway/CourseFeedbackAPI"
  retention_in_days = 30
}

# CloudWatch Log Group for Elastic Beanstalk
resource "aws_cloudwatch_log_group" "eb_logs" {
  name              = "/aws/elasticbeanstalk/course-feedback-env/var/log"
  retention_in_days = 30
}

# Existing API Gateway Stage (remove web_acl_arn)
resource "aws_api_gateway_stage" "v1" {
  depends_on           = [aws_api_gateway_deployment.api_deployment]
  rest_api_id          = aws_api_gateway_rest_api.feedback_api.id
  deployment_id        = aws_api_gateway_deployment.api_deployment.id
  stage_name           = "v1"

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway_logs.arn
    format          = "$context.identity.sourceIp $context.identity.caller $context.identity.user [$context.requestTime] \"$context.httpMethod $context.resourcePath $context.protocol\" $context.status $context.responseLength $context.requestId"
  }

  xray_tracing_enabled = true
}

# API Gateway Account Configuration (using LabRole)
resource "aws_api_gateway_account" "api_gateway_account" {
  cloudwatch_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/LabRole"
}

# CloudWatch Metrics and Alarms
resource "aws_cloudwatch_metric_alarm" "lambda_invocations_alarm" {
  alarm_name          = "lambda_invocations_low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "5"
  metric_name         = "Invocations"
  namespace           = "AWS/Lambda"
  period              = "300"  # 5 minutes
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "This metric monitors low Lambda invocations"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.notification.arn]
  ok_actions          = [aws_sns_topic.notification.arn]

  dimensions = {
    FunctionName = aws_lambda_function.feedback_processor.function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "api_gateway_4xx_alarm" {
  alarm_name          = "api_gateway_4xx_errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "5"
  metric_name         = "4XXError"
  namespace           = "AWS/ApiGateway"
  period              = "300"  # 5 minutes
  statistic           = "Sum"
  threshold           = "5"    # 5% of requests (adjust based on traffic)
  alarm_description   = "This metric monitors 4XX errors in API Gateway"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.notification.arn]
  ok_actions          = [aws_sns_topic.notification.arn]

  dimensions = {
    ApiName = aws_api_gateway_rest_api.feedback_api.name
    Stage   = "v1"
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu_alarm" {
  alarm_name          = "rds_high_cpu_utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "5"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"  # 5 minutes
  statistic           = "Average"
  threshold           = "80"   # 80% CPU
  alarm_description   = "This metric monitors high CPU utilization on RDS"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.notification.arn]
  ok_actions          = [aws_sns_topic.notification.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.mysql_instance.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_storage_alarm" {
  alarm_name          = "rds_low_free_storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "5"
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = "300"  # 5 minutes
  statistic           = "Average"
  threshold           = "10737418240"  # 10GB in bytes
  alarm_description   = "This metric monitors low free storage on RDS"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.notification.arn]
  ok_actions          = [aws_sns_topic.notification.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.mysql_instance.identifier
  }
}

# CloudTrail Configuration with S3 Bucket Policy
resource "aws_cloudtrail" "course_feedback_trail" {
  name                          = "course-feedback-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail_logs.arn}:*"
  cloud_watch_logs_role_arn     = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/LabRole"

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "course-feedback-cloudtrail-logs"
  acl    = "private"
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::course-feedback-cloudtrail-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = "arn:aws:s3:::course-feedback-cloudtrail-logs"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail_logs" {
  name              = "/aws/cloudtrail/course-feedback-trail"
  retention_in_days = 30
}

# Existing Web ACL (unchanged)
resource "aws_wafv2_web_acl" "course_feedback_waf" {
  name        = "CourseFeedbackWAF"
  scope       = "REGIONAL"  # Use "REGIONAL" for API Gateway
  description = "WAF for Course Feedback API"

  default_action {
    allow {}  # Default to allow all requests
  }

  rule {
    name     = "RateLimitRule"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 1000  # Limit to 1000 requests per 5 minutes
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "CourseFeedbackWAFMetric"
    sampled_requests_enabled   = true
  }
}

# New WAF Association
resource "aws_wafv2_web_acl_association" "api_gateway_waf_association" {
  resource_arn = aws_api_gateway_stage.v1.arn
  web_acl_arn  = aws_wafv2_web_acl.course_feedback_waf.arn
}

# Cognito User Pool for Authentication
resource "aws_cognito_user_pool" "course_feedback_pool" {
  name = "CourseFeedbackUserPool"

  # Password policy
  password_policy {
    minimum_length    = 8
    require_numbers   = true
    require_symbols   = false
    require_uppercase = true
    require_lowercase = true
  }

  # Email as a required attribute
  schema {
    attribute_data_type = "String"
    name                = "email"
    required            = true
    mutable             = true
  }

  # Custom attribute for user role (student/instructor)
  schema {
    attribute_data_type = "String"
    name                = "custom:role"
    required            = false
    mutable             = true
  }

  # Email verification
  auto_verified_attributes = ["email"]

  # MFA configuration
  mfa_configuration = "OPTIONAL"
  software_token_mfa_configuration {
    enabled = true
  }
}

# Cognito User Pool Client
resource "aws_cognito_user_pool_client" "course_feedback_client" {
  name         = "CourseFeedbackAppClient"
  user_pool_id = aws_cognito_user_pool.course_feedback_pool.id

  # No client secret for web apps
  generate_secret = false

  # Allowed OAuth flows and scopes
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["email", "openid", "profile", "aws.cognito.signin.user.admin"]

  # Callback and logout URLs (update with your web app URLs)
  callback_urls = ["https://your-web-app.com/callback"]
  logout_urls   = ["https://your-web-app.com/logout"]

  # Enable token refresh
  refresh_token_validity = 30

  # Enable MFA for this client
  prevent_user_existence_errors = "ENABLED"
  explicit_auth_flows           = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"]

  depends_on = [aws_cognito_user_pool.course_feedback_pool]
}

# DynamoDB Table for Session Store
resource "aws_dynamodb_table" "session_store" {
  name           = "SessionStore"
  billing_mode   = "PAY_PER_REQUEST"  # On-demand capacity
  hash_key       = "SessionId"

  attribute {
    name = "SessionId"
    type = "S"  # String
  }

  tags = {
    Name = "session-store"
  }
}