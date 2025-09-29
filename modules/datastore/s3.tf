resource "aws_s3_bucket" "this" {
  bucket        = local.s3_bucket_name
  acl           = "private"
  force_destroy = var.force_destroy_s3_bucket

  tags = merge(
    var.standard_tags,
    {
      Metaflow = "true"
    }
  )
}
