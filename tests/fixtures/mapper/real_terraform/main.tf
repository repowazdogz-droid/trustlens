terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
provider "aws" {
  region                      = "eu-west-2"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  access_key                  = "mock"
  secret_key                  = "mock"
}

resource "aws_iam_role" "dataset_worker" {
  name = "dataset-worker-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.eu-west-2.amazonaws.com/id/EXAMPLE" }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = { "oidc.eks.eu-west-2.amazonaws.com/id/EXAMPLE:sub" = "system:serviceaccount:ml:dataset-worker" } }
    }]
  })
}

resource "aws_iam_policy" "read_prod" {
  name = "read-prod-data"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject", "s3:ListBucket"], Resource = ["arn:aws:s3:::prod-data", "arn:aws:s3:::prod-data/*"] },
      { Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = "*" }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.dataset_worker.name
  policy_arn = aws_iam_policy.read_prod.arn
}

resource "aws_s3_bucket" "prod_data" { bucket = "prod-data" }
