data "aws_iam_policy_document" "metadata_svc_ecs_task_assume_role" {
  statement {
    effect = "Allow"

    principals {
      identifiers = [
        "ecs-tasks.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "metadata_ui_ecs_task_role" {
  name = "${var.resource_prefix}ui-ecs-task${var.resource_suffix}"
  # Read more about ECS' `task_role` and `execution_role` here https://stackoverflow.com/a/49947471
  description        = "This role is passed to AWS ECS' task definition as the `task_role`. This allows the running of the Metaflow Metadata Service to have the proper permissions to speak to other AWS resources."
  assume_role_policy = data.aws_iam_policy_document.metadata_svc_ecs_task_assume_role.json

  permissions_boundary = var.permissions_boundary

  tags = var.standard_tags
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
      var.datastore_s3_bucket_kms_key_arn
    ]
  }
}

data "aws_iam_policy_document" "custom_s3_batch" {
  statement {
    sid = "ObjectAccessMetadataService"

    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]

    resources = [
      "${var.s3_bucket_arn}/*",
      "${var.s3_bucket_arn}"
    ]
  }
}

data "aws_iam_policy_document" "deny_presigned_batch" {
  statement {
    sid = "DenyPresignedBatch"

    effect = "Deny"

    actions = [
      "s3:*"
    ]

    resources = [
      "*"
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

# Inline IAM Policies for metadata_ui_ecs_task_role (when use_inline_policies = true)
resource "aws_iam_role_policy" "grant_s3_kms" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "s3_kms"
  role   = aws_iam_role.metadata_ui_ecs_task_role.name
  policy = data.aws_iam_policy_document.s3_kms.json
}

resource "aws_iam_role_policy" "grant_custom_s3_batch" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "custom_s3"
  role   = aws_iam_role.metadata_ui_ecs_task_role.name
  policy = data.aws_iam_policy_document.custom_s3_batch.json
}

resource "aws_iam_role_policy" "grant_deny_presigned_batch" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "deny_presigned"
  role   = aws_iam_role.metadata_ui_ecs_task_role.name
  policy = data.aws_iam_policy_document.deny_presigned_batch.json
}

# Independent IAM Policies for metadata_ui_ecs_task_role (when use_inline_policies = false)
resource "aws_iam_policy" "metadata_ui_s3_kms_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${var.resource_prefix}ui-ecs-task${var.resource_suffix}-s3-kms"
  policy = data.aws_iam_policy_document.s3_kms.json
  tags   = var.standard_tags
}

resource "aws_iam_policy" "metadata_ui_custom_s3_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${var.resource_prefix}ui-ecs-task${var.resource_suffix}-custom-s3"
  policy = data.aws_iam_policy_document.custom_s3_batch.json
  tags   = var.standard_tags
}

resource "aws_iam_policy" "metadata_ui_deny_presigned_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${var.resource_prefix}ui-ecs-task${var.resource_suffix}-deny-presigned"
  policy = data.aws_iam_policy_document.deny_presigned_batch.json
  tags   = var.standard_tags
}

# Policy Attachments for metadata_ui_ecs_task_role (when use_inline_policies = false)
resource "aws_iam_role_policy_attachment" "metadata_ui_s3_kms_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.metadata_ui_ecs_task_role.name
  policy_arn = aws_iam_policy.metadata_ui_s3_kms_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "metadata_ui_custom_s3_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.metadata_ui_ecs_task_role.name
  policy_arn = aws_iam_policy.metadata_ui_custom_s3_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "metadata_ui_deny_presigned_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.metadata_ui_ecs_task_role.name
  policy_arn = aws_iam_policy.metadata_ui_deny_presigned_policy[0].arn
}
