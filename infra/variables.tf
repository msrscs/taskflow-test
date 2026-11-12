# Parametros de entrada. Nada de valor sensivel ou de rede fixo no codigo:
# os valores reais viriam de um terraform.tfvars (no .gitignore) ou de
# variaveis de ambiente TF_VAR_*.

variable "regiao" {
  description = "Regiao AWS onde os recursos seriam criados."
  type        = string
  default     = "us-east-1"
}

variable "ambiente" {
  description = "Nome do ambiente (vai nas tags e no nome dos recursos)."
  type        = string
  default     = "lab"

  validation {
    condition     = can(regex("^[a-z0-9-]{2,16}$", var.ambiente))
    error_message = "Use so letras minusculas, numeros e hifen (2 a 16 caracteres)."
  }
}

variable "nome_bucket" {
  description = "Prefixo do nome dos buckets (nomes de bucket S3 sao globais)."
  type        = string
  default     = "taskflow-devsecops-relatorios"
}

# CORRECAO da FALHA 6 do main.insecure.tf (SSH aberto para 0.0.0.0/0):
# o unico IP/faixa com acesso vem desta variavel, e a validacao RECUSA
# faixas abertas para a internet inteira.
variable "ip_permitido" {
  description = "Faixa CIDR autorizada a acessar a aplicacao (porta 443) e o SSH (porta 22). Ex.: IP da VPN em /32."
  type        = string

  validation {
    condition     = can(cidrhost(var.ip_permitido, 0))
    error_message = "ip_permitido precisa ser um CIDR valido, ex.: 203.0.113.10/32."
  }

  validation {
    condition     = !contains(["0.0.0.0/0", "::/0"], var.ip_permitido)
    error_message = "ip_permitido nao pode liberar a internet inteira (0.0.0.0/0 ou ::/0)."
  }
}

# CORRECAO da FALHA 7 (egress liberado): a saida tambem e restrita. A app
# nao fala direto com a internet; atualizacoes e APIs externas passam por um
# proxy de saida ou por VPC endpoints dentro desta faixa.
variable "cidr_saida" {
  description = "Faixa CIDR de destino permitida na saida (proxy de saida / VPC endpoints)."
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.cidr_saida, 0)) && !contains(["0.0.0.0/0", "::/0"], var.cidr_saida)
    error_message = "cidr_saida precisa ser um CIDR valido e nao pode ser a internet inteira."
  }
}

variable "vpc_id" {
  description = "ID da VPC onde o security group seria criado."
  type        = string
  default     = null
}
