# Versoes fixadas (mesmo principio do pin por SHA e por digest): o
# Terraform e o provider so mudam quando alguem altera este arquivo.
# O .terraform.lock.hcl (versionado) guarda o hash do provider baixado.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
  }

  # O estado (terraform.tfstate) pode conter dados sensiveis em texto puro.
  # Num projeto real ele ficaria num backend remoto criptografado, com trava
  # de concorrencia. Neste lab nao ha "apply" (so validate e scanners), entao
  # o backend local padrao basta; o .tfstate esta no .gitignore.
  #
  # backend "s3" {
  #   bucket       = "<bucket-do-state>"
  #   key          = "taskflow/terraform.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.regiao

  # Tags aplicadas a TODOS os recursos (governanca: dono, projeto, ambiente).
  default_tags {
    tags = {
      Projeto  = "taskflow-devsecops"
      Ambiente = var.ambiente
      Owner    = "msrscs"
      Gerencia = "terraform"
    }
  }
}
