terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.48.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "3.1.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.5.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "2.3.0"
    }
  }
  backend "http" {}
}

provider "aws" {}
provider "tls" {}


data "terraform_remote_state" "network" {
  backend = "http"

  config = {
    address  = "https://git.example.com/api/v4/projects/100/terraform/state/network"
    username = "gitlab-ci-token"
    password = var.REMOTE_STATE_PASSWORD
  }
}

data "aws_security_groups" "eks-example-sgs" {
  filter {
    name   = "group-name"
    values = [format("*%s*", aws_eks_cluster.eks-example.name)]
  }
}

resource "aws_eks_cluster" "eks-example" {
  name     = var.EKS_CLUSTER_NAME
  role_arn = aws_iam_role.eks-role.arn
  version  = var.EKS_VERSION
  vpc_config {
    subnet_ids = flatten([
      values(data.terraform_remote_state.network.outputs.public_networks)[*].id,
      values(data.terraform_remote_state.network.outputs.private_networks)[*].id
    ])
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = ["1.1.1.1/32"]
  }
  kubernetes_network_config {
    service_ipv4_cidr = "10.244.0.0/16"
  }
  tags = local.common_tags

  depends_on = [
    aws_iam_role.eks-role
  ]
}

data "tls_certificate" "eks-oidc-cert" {
  url = aws_eks_cluster.eks-example.identity[0].oidc[0].issuer
}


resource "aws_ec2_tag" "tag-public-subnets" {
  for_each = data.terraform_remote_state.network.outputs.public_networks

  resource_id = each.value.id
  key         = "kubernetes.io/role/elb"
  value       = 1
}

resource "aws_ec2_tag" "tag-private-subnets" {
  for_each = data.terraform_remote_state.network.outputs.private_networks

  resource_id = each.value.id
  key         = "kubernetes.io/role/internal-elb"
  value       = 1
}


resource "aws_key_pair" "eks-worker" {
  key_name   = "eks-worker-key"
  public_key = var.WORKER_SSH_PUBLIC_KEY
  tags       = local.common_tags
}

resource "aws_iam_openid_connect_provider" "eks-example" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks-oidc-cert.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.eks-example.identity[0].oidc[0].issuer
  tags = merge(
    local.common_tags,
    {
      Name = "EKS Example OIDC"
    }
  )
}

resource "aws_launch_template" "eks-example-node-group-lt" {
  name          = "EKSWorkerNodesLT"
  instance_type = "t3a.xlarge"
  key_name      = aws_key_pair.eks-worker.key_name

  vpc_security_group_ids = flatten([
    data.terraform_remote_state.network.outputs.sg-from-example.id,
    data.aws_security_groups.eks-example-sgs.ids
  ])

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 70
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags          = local.common_tags
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.common_tags
  }
  tags = local.common_tags
}

resource "aws_eks_node_group" "eks-example-node-group" {
  count = 3

  cluster_name    = aws_eks_cluster.eks-example.name
  node_group_name = format("example-workers-%s", values(data.terraform_remote_state.network.outputs.public_networks)[count.index].availability_zone)
  node_role_arn   = aws_iam_role.eks-node-group-role.arn
  subnet_ids      = [values(data.terraform_remote_state.network.outputs.public_networks)[count.index].id]

  launch_template {
    id      = aws_launch_template.eks-example-node-group-lt.id
    version = aws_launch_template.eks-example-node-group-lt.latest_version
  }

  scaling_config {
    desired_size = 1
    max_size     = 5
    min_size     = 1
  }

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }

  tags = local.common_tags

  depends_on = [
    aws_iam_role.eks-node-group-role,
    aws_key_pair.eks-worker
  ]
}

resource "aws_eks_addon" "eks-example-addons" {
  for_each      = local.eks_addons
  cluster_name  = aws_eks_cluster.eks-example.name
  addon_name    = each.key
  addon_version = each.value
  tags          = local.common_tags

  depends_on = [aws_eks_node_group.eks-example-node-group]
}

resource "aws_iam_role" "dlm_lifecycle_role" {
  name = "EksDLMLifecycleRole"
  tags = local.common_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "dlm.amazonaws.com"
        }
      },
    ]
  })

  inline_policy {
    name = "DLMLifecyclePolicy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "ec2:CreateSnapshot",
            "ec2:CreateSnapshots",
            "ec2:DeleteSnapshot",
            "ec2:DescribeInstances",
            "ec2:DescribeVolumes",
            "ec2:DescribeSnapshots"
          ]
          Effect   = "Allow"
          Resource = "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "ec2:CreateTags"
          ],
          "Resource" : "arn:aws:ec2:*::snapshot/*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "events:PutRule",
            "events:DeleteRule",
            "events:DescribeRule",
            "events:EnableRule",
            "events:DisableRule",
            "events:ListTargetsByRule",
            "events:PutTargets",
            "events:RemoveTargets"
          ],
          "Resource" : "arn:aws:events:*:*:rule/AwsDataLifecycleRule.managed-cwe.*"
        }
      ]
    })
  }
}

resource "aws_dlm_lifecycle_policy" "daily" {
  description        = "EKS Daily DLM lifecycle policy"
  execution_role_arn = aws_iam_role.dlm_lifecycle_role.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]

    schedule {
      name = "3 days of daily snapshot"

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["21:00"]
      }

      retain_rule {
        count = 3
      }

      tags_to_add = {
        SnapshotCreator = "EKS Daily Backup"
      }

      copy_tags = true
    }

    target_tags = {
      BackupStrategy = "daily"
    }
  }
  tags = merge(
    local.common_tags,
    {
      Name = "EKS Daily Backup"
    }
  )
}


output "endpoint" {
  value = aws_eks_cluster.eks-example.endpoint
}

output "eks-ca" {
  value = aws_eks_cluster.eks-example.certificate_authority[0].data
}

output "eks-cluster-name" {
  value = aws_eks_cluster.eks-example.name
}
