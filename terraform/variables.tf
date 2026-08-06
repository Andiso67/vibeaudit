variable "region" {
  description = "Región AWS donde se despliega"
  type        = string
  default     = "us-east-1"
}

variable "stack_name" {
  description = "Nombre del stack (tags y recursos)"
  type        = string
  default     = "vibeaudit"
}

variable "instance_type" {
  description = "Tipo de instancia EC2"
  type        = string
  default     = "t3.medium"
}

variable "volume_size_gb" {
  description = "Tamaño del disco raíz (gp3)"
  type        = number
  default     = 20
}

variable "ami_filter" {
  description = "Filtro para buscar la AMI Amazon Linux 2023 más reciente"
  type        = string
  default     = "al2023-ami-2023.*-x86_64"
}

variable "git_url" {
  description = "URL del repositorio a clonar en la instancia"
  type        = string
  default     = "https://github.com/Andiso67/vibeaudit.git"
}

variable "ssh_cidr" {
  description = "CIDR permitido para SSH (22). Recomendado tu IP (curl https://checkip.amazonaws.com)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "duckdns_host" {
  description = "Hostname DuckDNS sin el sufijo .duckdns.org (p. ej. vibeaudit)"
  type        = string
}

variable "duckdns_token" {
  description = "Token de DuckDNS (sensitive)"
  type        = string
  sensitive   = true
}

variable "postgres_password" {
  description = "Contraseña de Postgres en producción (sensitive)"
  type        = string
  sensitive   = true
}
