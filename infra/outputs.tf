output "bucket_dados" {
  description = "Nome do bucket de relatorios da TaskFlow"
  value       = aws_s3_bucket.dados.bucket
}

output "bucket_logs" {
  description = "Nome do bucket que recebe os logs de acesso"
  value       = aws_s3_bucket.logs.bucket
}

output "security_group_id" {
  description = "ID do security group da aplicacao"
  value       = aws_security_group.app.id
}
