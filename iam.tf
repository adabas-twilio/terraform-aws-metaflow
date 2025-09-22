data "aws_iam_policy_document" "batch_s3_task_role_assume_role" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]

    effect = "Allow"

    principals {
      identifiers = [
        "ecs-tasks.amazonaws.com",
      ]
      type = "Service"
    }
  }
}

resource "aws_iam_role" "batch_s3_task_role" {
  name = local.batch_s3_task_role_name

  description = "Role for AWS Batch to Access Amazon S3 [METAFLOW_ECS_S3_ACCESS_IAM_ROLE]"

  assume_role_policy = data.aws_iam_policy_document.batch_s3_task_role_assume_role.json

  permissions_boundary = var.permissions_boundary

  tags = var.tags
}

data "aws_iam_policy_document" "custom_s3_list_batch" {
  statement {
    sid = "BucketAccessBatch"
    actions = [
      "s3:ListBucket"
    ]

    effect = "Allow"

    resources = [
      module.metaflow-datastore.s3_bucket_arn
    ]
  }
}

data "aws_iam_policy_document" "custom_s3_batch" {
  statement {
    sid = "ObjectAccessBatch"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject"
    ]

    effect = "Allow"

    resources = [
      "${module.metaflow-datastore.s3_bucket_arn}/*"
    ]
  }
}

data "aws_iam_policy_document" "s3_kms" {
  statement {
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey"
    ]

    resources = [
      module.metaflow-datastore.datastore_s3_bucket_kms_key_arn
    ]
  }
}

data "aws_iam_policy_document" "deny_presigned_batch" {
  statement {
    sid = "DenyPresignedBatch"
    actions = [
      "s3:*"
    ]

    effect = "Deny"

    resources = [
      "*",
    ]

    condition {
      test = "StringNotEquals"
      values = [
        "REST-HEADER"
      ]
      variable = "s3:authType"
    }
  }
}

data "aws_iam_policy_document" "allow_sagemaker" {
  statement {
    sid = "AllowSagemakerCreate"
    actions = [
      "sagemaker:CreateTrainingJob"
    ]

    effect = "Allow"

    resources = [
      "arn:${var.iam_partition}:sagemaker:${local.aws_region}:${local.aws_account_id}:training-job/*",
    ]
  }

  statement {
    sid = "AllowSagemakerDescribe"
    actions = [
      "sagemaker:DescribeTrainingJob"
    ]

    effect = "Allow"

    resources = [
      "arn:${var.iam_partition}:sagemaker:${local.aws_region}:${local.aws_account_id}:training-job/*",
    ]
  }

  statement {
    sid = "AllowSagemakerDeploy"
    actions = [
      "sagemaker:CreateModel",
      "sagemaker:CreateEndpointConfig",
      "sagemaker:CreateEndpoint",
      "sagemaker:DescribeModel",
      "sagemaker:DescribeEndpoint",
      "sagemaker:InvokeEndpoint"
    ]

    effect = "Allow"

    resources = [
      "arn:${var.iam_partition}:sagemaker:${local.aws_region}:${local.aws_account_id}:endpoint/*",
      "arn:${var.iam_partition}:sagemaker:${local.aws_region}:${local.aws_account_id}:model/*",
      "arn:${var.iam_partition}:sagemaker:${local.aws_region}:${local.aws_account_id}:endpoint-config/*",
    ]
  }
}

data "aws_iam_policy_document" "iam_pass_role" {
  statement {
    sid = "AllowPassRole"
    actions = [
      "iam:PassRole",
    ]

    effect = "Allow"

    resources = [
      "*"
    ]

    condition {
      test = "StringEquals"
      values = [
        "sagemaker.amazonaws.com"
      ]
      variable = "iam:PassedToService"
    }
  }
}

data "aws_iam_policy_document" "dynamodb" {
  statement {
    sid = "Items"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:UpdateItem",
    ]

    effect = "Allow"

    resources = [
      module.metaflow-step-functions.metaflow_step_functions_dynamodb_table_arn
    ]
  }
}

data "aws_iam_policy_document" "cloudwatch" {
  statement {
    sid = "AllowPutLogs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    effect = "Allow"

    resources = [
      "*"
    ]
  }
}

# Inline IAM Policies for batch_s3_task_role (when use_inline_policies = true)
resource "aws_iam_role_policy" "grant_custom_s3_list_batch" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "s3_list"
  role   = aws_iam_role.batch_s3_task_role.name
  policy = data.aws_iam_policy_document.custom_s3_list_batch.json
}

resource "aws_iam_role_policy" "grant_custom_s3_batch" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "custom_s3"
  role   = aws_iam_role.batch_s3_task_role.name
  policy = data.aws_iam_policy_document.custom_s3_batch.json
}

resource "aws_iam_role_policy" "grant_s3_kms" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "s3_kms"
  role   = aws_iam_role.batch_s3_task_role.name
  policy = data.aws_iam_policy_document.s3_kms.json
}

resource "aws_iam_role_policy" "grant_deny_presigned_batch" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "deny_presigned"
  role   = aws_iam_role.batch_s3_task_role.name
  policy = data.aws_iam_policy_document.deny_presigned_batch.json
}

resource "aws_iam_role_policy" "grant_allow_sagemaker" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "sagemaker"
  role   = aws_iam_role.batch_s3_task_role.name
  policy = data.aws_iam_policy_document.allow_sagemaker.json
}

resource "aws_iam_role_policy" "grant_iam_pass_role" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "iam_pass_role"
  role   = aws_iam_role.batch_s3_task_role.name
  policy = data.aws_iam_policy_document.iam_pass_role.json
}

resource "aws_iam_role_policy" "grant_dynamodb" {
  count  = var.use_inline_policies && var.enable_step_functions ? 1 : 0
  name   = "dynamodb"
  role   = aws_iam_role.batch_s3_task_role.name
  policy = data.aws_iam_policy_document.dynamodb.json
}

resource "aws_iam_role_policy" "grant_cloudwatch" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "cloudwatch"
  role   = aws_iam_role.batch_s3_task_role.name
  policy = data.aws_iam_policy_document.cloudwatch.json
}

# Independent IAM Policies for batch_s3_task_role (when use_inline_policies = false)
resource "aws_iam_policy" "batch_s3_list_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${local.batch_s3_task_role_name}-s3-list"
  policy = data.aws_iam_policy_document.custom_s3_list_batch.json
  tags   = var.tags
}

resource "aws_iam_policy" "batch_s3_custom_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${local.batch_s3_task_role_name}-custom-s3"
  policy = data.aws_iam_policy_document.custom_s3_batch.json
  tags   = var.tags
}

resource "aws_iam_policy" "batch_s3_kms_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${local.batch_s3_task_role_name}-s3-kms"
  policy = data.aws_iam_policy_document.s3_kms.json
  tags   = var.tags
}

resource "aws_iam_policy" "batch_deny_presigned_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${local.batch_s3_task_role_name}-deny-presigned"
  policy = data.aws_iam_policy_document.deny_presigned_batch.json
  tags   = var.tags
}

resource "aws_iam_policy" "batch_sagemaker_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${local.batch_s3_task_role_name}-sagemaker"
  policy = data.aws_iam_policy_document.allow_sagemaker.json
  tags   = var.tags
}

resource "aws_iam_policy" "batch_iam_pass_role_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${local.batch_s3_task_role_name}-iam-pass-role"
  policy = data.aws_iam_policy_document.iam_pass_role.json
  tags   = var.tags
}

resource "aws_iam_policy" "batch_dynamodb_policy" {
  count  = !var.use_inline_policies && var.enable_step_functions ? 1 : 0
  name   = "${local.batch_s3_task_role_name}-dynamodb"
  policy = data.aws_iam_policy_document.dynamodb.json
  tags   = var.tags
}

resource "aws_iam_policy" "batch_cloudwatch_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${local.batch_s3_task_role_name}-cloudwatch"
  policy = data.aws_iam_policy_document.cloudwatch.json
  tags   = var.tags
}

# Policy Attachments for batch_s3_task_role (when use_inline_policies = false)
resource "aws_iam_role_policy_attachment" "batch_s3_list_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.batch_s3_task_role.name
  policy_arn = aws_iam_policy.batch_s3_list_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "batch_s3_custom_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.batch_s3_task_role.name
  policy_arn = aws_iam_policy.batch_s3_custom_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "batch_s3_kms_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.batch_s3_task_role.name
  policy_arn = aws_iam_policy.batch_s3_kms_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "batch_deny_presigned_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.batch_s3_task_role.name
  policy_arn = aws_iam_policy.batch_deny_presigned_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "batch_sagemaker_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.batch_s3_task_role.name
  policy_arn = aws_iam_policy.batch_sagemaker_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "batch_iam_pass_role_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.batch_s3_task_role.name
  policy_arn = aws_iam_policy.batch_iam_pass_role_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "batch_dynamodb_attachment" {
  count      = !var.use_inline_policies && var.enable_step_functions ? 1 : 0
  role       = aws_iam_role.batch_s3_task_role.name
  policy_arn = aws_iam_policy.batch_dynamodb_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "batch_cloudwatch_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.batch_s3_task_role.name
  policy_arn = aws_iam_policy.batch_cloudwatch_policy[0].arn
}
