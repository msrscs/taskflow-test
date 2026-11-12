# =============================================================================
# infra/main.tf - infraestrutura da TaskFlow, CORRIGIDA a partir do
# main.insecure.tf do Modulo 5 (Encontro 12).
#
# Somente para validacao (terraform validate, Checkov, Trivy config). Nao ha
# "terraform apply" neste lab: nenhum recurso e criado em conta AWS.
#
# O que o PDF pede e onde esta:
#   - bucket privado ........... aws_s3_bucket_public_access_block (4 x true)
#                                + aws_s3_bucket_ownership_controls (ACL desligada)
#   - criptografado ............ SSE-KMS com chave propria e rotacao anual
#   - versionado ............... aws_s3_bucket_versioning = Enabled
#   - com logging .............. aws_s3_bucket_logging -> bucket de logs
#   - SG restrito a variavel ... ingress so de var.ip_permitido
#
# Comparado ao main.insecure.tf:
#   FALHA 1 (sem tags) ............ default_tags no provider (versions.tf)
#   FALHA 2 (public access block) . os 4 bloqueios = true, nos dois buckets
#   FALHA 3 (ACL public-read) ..... ACLs desligadas (BucketOwnerEnforced)
#   FALHA 4 (sem criptografia) .... SSE-KMS + bucket key
#   FALHA 5 (sem versionamento) ... versionamento habilitado
#   FALHA 6 (SSH 0.0.0.0/0) ....... ingress so de var.ip_permitido (validada)
#   FALHA 7 (egress liberado) ..... egress so HTTPS e so para var.cidr_saida
#   + (exigencia do PDF) .......... logging de acesso do bucket
#
# Todo "#checkov:skip" e "#trivy:ignore" fica no proprio recurso, com a
# justificativa escrita.
# =============================================================================

data "aws_caller_identity" "atual" {}

locals {
  bucket_dados = "${var.nome_bucket}-${var.ambiente}"
  bucket_logs  = "${var.nome_bucket}-${var.ambiente}-logs"
}

# -----------------------------------------------------------------------------
# Chave KMS (criptografia em repouso dos dois buckets)
# -----------------------------------------------------------------------------
resource "aws_kms_key" "s3" {
  description             = "Criptografia dos buckets da TaskFlow"
  deletion_window_in_days = 30
  # Rotacao automatica anual da chave.
  enable_key_rotation = true

  # Politica explicita: so a propria conta administra e usa a chave.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AdministracaoPelaPropriaConta"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.atual.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "ServicoDeLogsDoS3"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.atual.account_id }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "s3" {
  name          = "alias/taskflow-${var.ambiente}-s3"
  target_key_id = aws_kms_key.s3.key_id
}

# -----------------------------------------------------------------------------
# Bucket de LOGS de acesso (destino do logging do bucket de dados)
# -----------------------------------------------------------------------------
# trivy:ignore:AWS-0089 -> mesma justificativa do CKV_AWS_18 abaixo: este e o
# bucket de destino dos logs de acesso; logar o acesso a ele mesmo geraria um
# laco infinito de logs.
#trivy:ignore:AWS-0089
resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_18:Este E o bucket de destino dos logs de acesso; registrar o acesso a ele em si mesmo geraria um laco infinito de logs.
  #checkov:skip=CKV_AWS_144:Replicacao entre regioes fora do escopo do lab (custo); os logs ja sao versionados e criptografados.
  #checkov:skip=CKV2_AWS_62:Notificacoes de evento nao tem consumidor neste projeto; os logs sao lidos sob demanda na investigacao.
  bucket = local.bucket_logs
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    # ACLs desligadas: acesso so por politica (IAM / bucket policy).
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "retencao-dos-logs"
    status = "Enabled"
    filter {}

    # Logs de acesso guardados por 1 ano (prazo usado para investigar
    # incidentes) e depois apagados, inclusive as versoes antigas.
    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Somente o servico de logging do S3, vindo do bucket de dados desta conta,
# pode gravar aqui; e so por HTTPS.
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EscritaDosLogsDeAcesso"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/access-logs/*"
        Condition = {
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.dados.arn }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.atual.account_id }
        }
      },
      {
        Sid       = "SomenteHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# -----------------------------------------------------------------------------
# Bucket de DADOS (relatorios da TaskFlow): privado, criptografado,
# versionado e com logging
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "dados" {
  #checkov:skip=CKV_AWS_144:Replicacao entre regioes fora do escopo do lab (custo); a protecao contra perda vem do versionamento.
  #checkov:skip=CKV2_AWS_62:Notificacoes de evento nao tem consumidor neste projeto (nenhum processamento dispara a partir de upload).
  bucket = local.bucket_dados
}

resource "aws_s3_bucket_public_access_block" "dados" {
  bucket                  = aws_s3_bucket.dados.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "dados" {
  bucket = aws_s3_bucket.dados.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dados" {
  bucket = aws_s3_bucket.dados.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "dados" {
  bucket = aws_s3_bucket.dados.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "dados" {
  bucket        = aws_s3_bucket.dados.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "dados" {
  bucket = aws_s3_bucket.dados.id

  rule {
    id     = "limpeza-de-versoes"
    status = "Enabled"
    filter {}

    # A versao atual fica para sempre; versoes antigas (sobrescritas ou
    # apagadas) ficam 90 dias para permitir recuperacao e depois saem.
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "dados" {
  bucket = aws_s3_bucket.dados.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "SomenteHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.dados.arn, "${aws_s3_bucket.dados.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.dados]
}

# -----------------------------------------------------------------------------
# Security group da aplicacao: entrada so da faixa autorizada
# -----------------------------------------------------------------------------
resource "aws_security_group" "app" {
  #checkov:skip=CKV2_AWS_5:Nao ha instancia/ENI neste lab (sem apply); o SG seria anexado a instancia da aplicacao no ambiente real.
  name        = "taskflow-${var.ambiente}-app"
  description = "TaskFlow: HTTPS e SSH somente a partir de var.ip_permitido"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS da aplicacao, so da faixa autorizada"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = var.ip_permitido
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.app.id
  description       = "SSH de administracao, so da faixa autorizada (VPN/bastion)"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = var.ip_permitido
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.app.id
  description       = "Saida apenas HTTPS para o proxy de saida / VPC endpoints"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = var.cidr_saida
}
