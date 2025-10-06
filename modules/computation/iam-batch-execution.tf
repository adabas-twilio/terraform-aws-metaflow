# Reference existing service-linked roles instead of creating them
# The Auto Scaling service-linked role is typically created automatically by AWS
# when Auto Scaling is first used in an account, or can be pre-created manually

# Only create the service-linked role if explicitly requested and it doesn't exist
resource "aws_iam_service_linked_role" "autoscaling" {
  count            = var.create_service_linked_roles ? 1 : 0
  aws_service_name = "autoscaling.amazonaws.com"
  custom_suffix    = ""
  description      = "Service-linked role for Auto Scaling used by AWS Batch"
  lifecycle {
    ignore_changes = [tags, tags_all]
  }
}

data "aws_iam_policy_document" "batch_execution_role_assume_role" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]

    effect = "Allow"

    principals {
      identifiers = [
        "batch.amazonaws.com",
      ]
      type = "Service"
    }
  }
}

resource "aws_iam_role" "batch_execution_role" {
  name = local.batch_execution_role_name
  # Learn more by reading this Terraform documentation https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/batch_compute_environment#argument-reference
  # Learn more by reading this AWS Batch documentation https://docs.aws.amazon.com/batch/latest/userguide/service_IAM_role.html
  description = "This role is passed to AWS Batch as a `service_role`. This allows AWS Batch to make calls to other AWS services on our behalf."

  assume_role_policy = data.aws_iam_policy_document.batch_execution_role_assume_role.json

  permissions_boundary = var.permissions_boundary

  tags = var.standard_tags
}

data "aws_iam_policy_document" "iam_pass_role" {
  statement {
    actions = [
      "iam:PassRole"
    ]

    effect = "Allow"

    resources = [
      "*"
    ]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com", "ec2.amazonaws.com.cn", "ecs-tasks.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "custom_access_policy" {
  statement {
    actions = [
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeInstanceStatus",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeKeyPairs",
      "ec2:DescribeImages",
      "ec2:DescribeImageAttribute",
      "ec2:DescribeSpotInstanceRequests",
      "ec2:DescribeSpotFleetInstances",
      "ec2:DescribeSpotFleetRequests",
      "ec2:DescribeSpotPriceHistory",
      "ec2:DescribeVpcClassicLink",
      "ec2:DescribeLaunchTemplates",
      "ec2:CreateTags",
      "ec2:DescribeVpcAttribute",
      "ssm:GetParameters",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:CreateLaunchTemplate",
      "ec2:DeleteLaunchTemplate",
      "ec2:RequestSpotFleet",
      "ec2:CancelSpotFleetRequests",
      "ec2:ModifySpotFleetRequest",
      "ec2:TerminateInstances",
      "ec2:RunInstances",
      "autoscaling:DescribeAccountLimits",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:CreateLaunchConfiguration",
      "autoscaling:CreateAutoScalingGroup",
      "autoscaling:UpdateAutoScalingGroup",
      "autoscaling:SetDesiredCapacity",
      "autoscaling:DeleteLaunchConfiguration",
      "autoscaling:DeleteAutoScalingGroup",
      "autoscaling:CreateOrUpdateTags",
      "autoscaling:SuspendProcesses",
      "autoscaling:PutNotificationConfiguration",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "ecs:DescribeClusters",
      "ecs:DescribeContainerInstances",
      "ecs:DescribeTaskDefinition",
      "ecs:DescribeTasks",
      "ecs:ListClusters",
      "ecs:ListContainerInstances",
      "ecs:ListTaskDefinitionFamilies",
      "ecs:ListTaskDefinitions",
      "ecs:ListTasks",
      "ecs:CreateCluster",
      "ecs:DeleteCluster",
      "ecs:RegisterTaskDefinition",
      "ecs:DeregisterTaskDefinition",
      "ecs:RunTask",
      "ecs:StartTask",
      "ecs:StopTask",
      "ecs:UpdateContainerAgent",
      "ecs:DeregisterContainerInstance",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "iam:GetInstanceProfile",
      "iam:GetRole",
    ]

    effect = "Allow"

    resources = [
      "*"
    ]
  }
}

data "aws_iam_policy_document" "iam_custom_policies" {
  # Only include CreateServiceLinkedRole permission if we're not pre-creating the roles
  dynamic "statement" {
    for_each = var.create_service_linked_roles ? [] : [1]
    content {
      actions = [
        "iam:CreateServiceLinkedRole"
      ]

      effect = "Allow"

      resources = [
        "*",
      ]

      condition {
        test     = "StringEquals"
        variable = "iam:AWSServiceName"
        values   = ["autoscaling.amazonaws.com", "ecs.amazonaws.com"]
      }
    }
  }
}

data "aws_iam_policy_document" "ec2_custom_policies" {
  statement {
    actions = [
      "ec2:CreateTags"
    ]

    effect = "Allow"

    resources = [
      "*",
    ]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["RunInstances"]
    }
  }
}

# Inline IAM Policies for batch_execution_role (when use_inline_policies = true)
resource "aws_iam_role_policy" "grant_iam_pass_role" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "iam_pass_role"
  role   = aws_iam_role.batch_execution_role.name
  policy = data.aws_iam_policy_document.iam_pass_role.json
}

resource "aws_iam_role_policy" "grant_custom_access_policy" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "custom_access"
  role   = aws_iam_role.batch_execution_role.name
  policy = data.aws_iam_policy_document.custom_access_policy.json
}

resource "aws_iam_role_policy" "grant_iam_custom_policies" {
  count  = var.use_inline_policies && !var.create_service_linked_roles ? 1 : 0
  name   = "iam_custom"
  role   = aws_iam_role.batch_execution_role.name
  policy = data.aws_iam_policy_document.iam_custom_policies.json
}

resource "aws_iam_role_policy" "grant_ec2_custom_policies" {
  count  = var.use_inline_policies ? 1 : 0
  name   = "ec2_custom"
  role   = aws_iam_role.batch_execution_role.name
  policy = data.aws_iam_policy_document.ec2_custom_policies.json
}

# Independent IAM Policies for batch_execution_role (when use_inline_policies = false)
resource "aws_iam_policy" "batch_execution_iam_pass_role_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${local.batch_execution_role_name}-iam-pass-role"
  policy = data.aws_iam_policy_document.iam_pass_role.json
  tags   = var.standard_tags
}

resource "aws_iam_policy" "batch_execution_custom_access_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${local.batch_execution_role_name}-custom-access"
  policy = data.aws_iam_policy_document.custom_access_policy.json
  tags   = var.standard_tags
}

resource "aws_iam_policy" "batch_execution_iam_custom_policy" {
  count  = !var.use_inline_policies && !var.create_service_linked_roles ? 1 : 0
  name   = "${local.batch_execution_role_name}-iam-custom"
  policy = data.aws_iam_policy_document.iam_custom_policies.json
  tags   = var.standard_tags
}

resource "aws_iam_policy" "batch_execution_ec2_custom_policy" {
  count  = var.use_inline_policies ? 0 : 1
  name   = "${local.batch_execution_role_name}-ec2-custom"
  policy = data.aws_iam_policy_document.ec2_custom_policies.json
  tags   = var.standard_tags
}

# Policy Attachments for batch_execution_role (when use_inline_policies = false)
resource "aws_iam_role_policy_attachment" "batch_execution_iam_pass_role_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.batch_execution_role.name
  policy_arn = aws_iam_policy.batch_execution_iam_pass_role_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "batch_execution_custom_access_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.batch_execution_role.name
  policy_arn = aws_iam_policy.batch_execution_custom_access_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "batch_execution_iam_custom_attachment" {
  count      = !var.use_inline_policies && !var.create_service_linked_roles ? 1 : 0
  role       = aws_iam_role.batch_execution_role.name
  policy_arn = aws_iam_policy.batch_execution_iam_custom_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "batch_execution_ec2_custom_attachment" {
  count      = var.use_inline_policies ? 0 : 1
  role       = aws_iam_role.batch_execution_role.name
  policy_arn = aws_iam_policy.batch_execution_ec2_custom_policy[0].arn
}
