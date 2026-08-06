output "instance_id" {
  description = "ID de la instancia EC2"
  value       = aws_instance.vibeaudit.id
}

output "public_ip" {
  description = "IP pública elástica"
  value       = aws_eip.vibeaudit.public_ip
}

output "dashboard_url" {
  description = "URL del dashboard"
  value       = "http://${var.duckdns_host}.duckdns.org:3000"
}

output "api_health_url" {
  description = "URL de health de la API"
  value       = "http://${var.duckdns_host}.duckdns.org:8000/api/health"
}

output "sonarqube_url" {
  description = "URL de SonarQube (admin/admin, cambia el password)"
  value       = "http://${var.duckdns_host}.duckdns.org:9000"
}

output "ssh_command" {
  description = "Acceso SSH a la instancia"
  value       = "ssh -i ${var.stack_name}-key.pem ec2-user@${aws_eip.vibeaudit.public_ip}"
}
