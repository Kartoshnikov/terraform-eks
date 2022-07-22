data "aws_region" "current" {}

provider "kubernetes" {
  host                   = aws_eks_cluster.eks-example.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.eks-example.certificate_authority[0].data)
  exec {
    api_version = "client.authentication.k8s.io/v1alpha1"
    args        = ["eks", "get-token", "--cluster-name", aws_eks_cluster.eks-example.name]
    command     = "aws"
  }
}

provider "helm" {
  kubernetes {
    host                   = aws_eks_cluster.eks-example.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.eks-example.certificate_authority[0].data)
    exec {
      api_version = "client.authentication.k8s.io/v1alpha1"
      args        = ["eks", "get-token", "--cluster-name", aws_eks_cluster.eks-example.name]
      command     = "aws"
    }
  }
}

resource "helm_release" "aws-ebs-csi-driver" {
  name       = "aws-ebs-csi-driver"
  repository = "https://kubernetes-sigs.github.io/aws-ebs-csi-driver"
  chart      = "aws-ebs-csi-driver"
  namespace  = "kube-system"

  values = [
    "${templatefile(
      "${path.module}/conf/aws-ebs-csi-driver.yml.tftpl",
      {
        role_arn   = "${aws_iam_role.aws-ebs-csi-driver.arn}",
        repo_url   = "${local.ecr_registry_address[data.aws_region.current.name]}",
        extra_tags = local.common_tags
      }
    )}"
  ]

  depends_on = [
    aws_eks_node_group.eks-example-node-group
  ]
}

resource "helm_release" "aws-load-balancer-controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"

  values = [
    "${templatefile(
      "${path.module}/conf/aws-load-balancer-controller.yml.tftpl",
      {
        role_arn     = "${aws_iam_role.aws-lb-controller.arn}",
        repo_url     = "${local.ecr_registry_address[data.aws_region.current.name]}",
        cluster_name = "${aws_eks_cluster.eks-example.name}"
      }
    )}"
  ]

  depends_on = [
    aws_eks_node_group.eks-example-node-group
  ]
}

resource "kubernetes_secret" "example-tls" {
  metadata {
    name      = "example-tls"
    namespace = "default"
  }
  type = "kubernetes.io/tls"
  binary_data = {
    "tls.crt" = var.EXAMPLE_CRT
    "tls.key" = var.EXAMPLE_KEY
  }
}

resource "helm_release" "ingress-nginx" {
  name             = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  namespace        = "ingress-nginx"
  create_namespace = true

  values = [
    "${templatefile(
      "${path.module}/conf/ingress-nginx.values.yml.tftpl",
      {
        extra_tags = "${join(",", [for k, v in local.common_tags : "${k}=${v}"])}"
      }
    )}"
  ]

  depends_on = [
    aws_eks_node_group.eks-example-node-group
  ]
}

resource "null_resource" "run_kubeclt_apply" {
  triggers = {
    esk_cluster_id = "${aws_eks_cluster.eks-example.id}"
  }

  provisioner "local-exec" {
    command = <<-EOT
      aws eks update-kubeconfig --name $TF_VAR_EKS_CLUSTER_NAME
      kubectl apply -f https://raw.githubusercontent.com/aws/eks-charts/master/stable/aws-load-balancer-controller/crds/crds.yaml;
      kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/master/calico-operator.yaml;
      kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/master/calico-crs.yaml;
    EOT
  }
}
