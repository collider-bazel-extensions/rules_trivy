# A registry module: Trivy would download it to evaluate it. In a test it
# can't (no network), and says so.
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
}
