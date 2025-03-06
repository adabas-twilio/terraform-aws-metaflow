resource "aws_s3_bucket" "this" {
  bucket        = local.s3_bucket_name
  acl           = "private"
  force_destroy = var.force_destroy_s3_bucket
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.s3.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }

  tags = merge(
    var.standard_tags,
    {
      Metaflow = "true"
    }
  )
}
