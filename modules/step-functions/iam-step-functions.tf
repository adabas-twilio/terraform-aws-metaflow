data "aws_iam_policy_document" "step_functions_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      identifiers = [
        "states.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

data "aws_iam_policy_document" "step_functions_batch_policy" {
  statement {
    actions = [
      "batch:TerminateJob",
      "batch:DescribeJobs",
      "batch:DescribeJobDefinitions",
      "batch:DescribeJobQueues",
      "batch:RegisterJobDefinition",
      "batch:TagResource"
    ]

    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "batch:SubmitJob"
    ]

    resources = [
      var.batch_job_queue_arn,
      "arn:${var.iam_partition}:batch:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:job-definition/*"
    ]
  }
}

data "aws_iam_policy_document" "step_functions_s3" {
  statement {
    actions = [
      "s3:ListBucket"
    ]

    resources = [
      var.s3_bucket_arn
    ]
  }

  statement {
    actions = [
      "s3:*Object"
    ]

    resources = [
      var.s3_bucket_arn, "${var.s3_bucket_arn}/*"
    ]
  }

  statement {
    actions = [
      "kms:Decrypt"
    ]

    resources = [
      var.s3_bucket_kms_arn
    ]
  }
}

data "aws_iam_policy_document" "step_functions_cloudwatch" {
  statement {
    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups"
    ]

    resources = [
      "*"
    ]
  }
}

data "aws_iam_policy_document" "step_functions_eventbridge" {
  statement {
    actions = [
      "events:PutTargets",
      "events:DescribeRule"
    ]

    resources = [
      "arn:${var.iam_partition}:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:rule/StepFunctionsGetEventsForBatchJobsRule",
    ]
  }

  statement {
    actions = [
      "events:PutRule"
    ]

    resources = [
      "arn:${var.iam_partition}:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:rule/StepFunctionsGetEventsForBatchJobsRule"
    ]

    condition {
      test     = "StringEquals"
      variable = "events:detail-type"
      values   = ["Batch Job State Change"]
    }
  }
}

data "aws_iam_policy_document" "step_functions_dynamodb" {
  statement {
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:UpdateItem"
    ]

    resources = [
      join("", [for arn in aws_dynamodb_table.step_functions_state_table.*.arn : arn])
    ]
  }
}

resource "aws_iam_role" "step_functions_role" {
  count              = var.active ? 1 : 0
  name               = "${var.resource_prefix}step_functions_role${var.resource_suffix}"
  description        = "IAM role for AWS Step Functions to access AWS resources (AWS Batch, AWS DynamoDB)."
  assume_role_policy = data.aws_iam_policy_document.step_functions_assume_role_policy.json

  permissions_boundary = var.permissions_boundary

  tags = var.standard_tags
}

# Inline IAM Policies for step_functions_role (when use_inline_policies = true)
resource "aws_iam_role_policy" "step_functions_batch" {
  count  = var.active && var.use_inline_policies ? 1 : 0
  name   = "aws_batch"
  role   = aws_iam_role.step_functions_role[0].id
  policy = data.aws_iam_policy_document.step_functions_batch_policy.json
}

resource "aws_iam_role_policy" "step_functions_s3" {
  count  = var.active && var.use_inline_policies ? 1 : 0
  name   = "s3"
  role   = aws_iam_role.step_functions_role[0].id
  policy = data.aws_iam_policy_document.step_functions_s3.json
}

resource "aws_iam_role_policy" "step_functions_cloudwatch" {
  count  = var.active && var.use_inline_policies ? 1 : 0
  name   = "cloudwatch"
  role   = aws_iam_role.step_functions_role[0].id
  policy = data.aws_iam_policy_document.step_functions_cloudwatch.json
}

resource "aws_iam_role_policy" "step_functions_eventbridge" {
  count  = var.active && var.use_inline_policies ? 1 : 0
  name   = "event_bridge"
  role   = aws_iam_role.step_functions_role[0].id
  policy = data.aws_iam_policy_document.step_functions_eventbridge.json
}

resource "aws_iam_role_policy" "step_functions_dynamodb" {
  count  = var.active && var.use_inline_policies ? 1 : 0
  name   = "dynamodb"
  role   = aws_iam_role.step_functions_role[0].id
  policy = data.aws_iam_policy_document.step_functions_dynamodb.json
}

# Independent IAM Policies for step_functions_role (when use_inline_policies = false)
resource "aws_iam_policy" "step_functions_batch_policy" {
  count  = var.active && !var.use_inline_policies ? 1 : 0
  name   = "${var.resource_prefix}step_functions_role${var.resource_suffix}-aws-batch"
  policy = data.aws_iam_policy_document.step_functions_batch_policy.json
  tags   = var.standard_tags
}

resource "aws_iam_policy" "step_functions_s3_policy" {
  count  = var.active && !var.use_inline_policies ? 1 : 0
  name   = "${var.resource_prefix}step_functions_role${var.resource_suffix}-s3"
  policy = data.aws_iam_policy_document.step_functions_s3.json
  tags   = var.standard_tags
}

resource "aws_iam_policy" "step_functions_cloudwatch_policy" {
  count  = var.active && !var.use_inline_policies ? 1 : 0
  name   = "${var.resource_prefix}step_functions_role${var.resource_suffix}-cloudwatch"
  policy = data.aws_iam_policy_document.step_functions_cloudwatch.json
  tags   = var.standard_tags
}

resource "aws_iam_policy" "step_functions_eventbridge_policy" {
  count  = var.active && !var.use_inline_policies ? 1 : 0
  name   = "${var.resource_prefix}step_functions_role${var.resource_suffix}-event-bridge"
  policy = data.aws_iam_policy_document.step_functions_eventbridge.json
  tags   = var.standard_tags
}

resource "aws_iam_policy" "step_functions_dynamodb_policy" {
  count  = var.active && !var.use_inline_policies ? 1 : 0
  name   = "${var.resource_prefix}step_functions_role${var.resource_suffix}-dynamodb"
  policy = data.aws_iam_policy_document.step_functions_dynamodb.json
  tags   = var.standard_tags
}

# Policy Attachments for step_functions_role (when use_inline_policies = false)
resource "aws_iam_role_policy_attachment" "step_functions_batch_attachment" {
  count      = var.active && !var.use_inline_policies ? 1 : 0
  role       = aws_iam_role.step_functions_role[0].id
  policy_arn = aws_iam_policy.step_functions_batch_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "step_functions_s3_attachment" {
  count      = var.active && !var.use_inline_policies ? 1 : 0
  role       = aws_iam_role.step_functions_role[0].id
  policy_arn = aws_iam_policy.step_functions_s3_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "step_functions_cloudwatch_attachment" {
  count      = var.active && !var.use_inline_policies ? 1 : 0
  role       = aws_iam_role.step_functions_role[0].id
  policy_arn = aws_iam_policy.step_functions_cloudwatch_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "step_functions_eventbridge_attachment" {
  count      = var.active && !var.use_inline_policies ? 1 : 0
  role       = aws_iam_role.step_functions_role[0].id
  policy_arn = aws_iam_policy.step_functions_eventbridge_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "step_functions_dynamodb_attachment" {
  count      = var.active && !var.use_inline_policies ? 1 : 0
  role       = aws_iam_role.step_functions_role[0].id
  policy_arn = aws_iam_policy.step_functions_dynamodb_policy[0].arn
}
