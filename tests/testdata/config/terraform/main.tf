resource "aws_s3_bucket" "logs" {
  bucket = "rules-trivy-example-logs"
  acl    = "public-read"
}
