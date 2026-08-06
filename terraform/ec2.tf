data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = [var.ami_filter]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "tls_private_key" "vibeaudit" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "vibeaudit" {
  key_name   = "${var.stack_name}-key"
  public_key = tls_private_key.vibeaudit.public_key_openssh
}

resource "local_file" "vibeaudit_pem" {
  filename        = "${path.module}/../${var.stack_name}-key.pem"
  content         = tls_private_key.vibeaudit.private_key_pem
  file_permission = "0600"
}

resource "aws_instance" "vibeaudit" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.vibeaudit.key_name
  vpc_security_group_ids = [aws_security_group.vibeaudit.id]

  user_data = templatefile("${path.module}/user-data.sh.tpl", {
    duckdns_host      = var.duckdns_host
    duckdns_token     = var.duckdns_token
    postgres_password = var.postgres_password
    git_url           = var.git_url
  })

  user_data_replace_on_change = true

  root_block_device {
    volume_size = var.volume_size_gb
    volume_type = "gp3"
  }

  tags = { Name = var.stack_name }

  depends_on = [local_file.vibeaudit_pem]
}

resource "aws_eip" "vibeaudit" {
  instance = aws_instance.vibeaudit.id
  domain   = "vpc"

  tags = { Name = var.stack_name }
}

resource "null_resource" "duckdns_update" {
  triggers = {
    eip = aws_eip.vibeaudit.public_ip
  }

  provisioner "local-exec" {
    command = "curl -s 'https://www.duckdns.org/update?domains=${var.duckdns_host}&token=${var.duckdns_token}&ip=${aws_eip.vibeaudit.public_ip}'"
  }

  depends_on = [aws_eip.vibeaudit]
}
