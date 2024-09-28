provider "aws" {
  region = "ap-northeast-1"
}

data "http" "icanhazip" {
  url = "http://ipv4.icanhazip.com"
}

resource "aws_key_pair" "deployer" {
  key_name   = "deployer-key"
  public_key = file("~/.ssh/id_ed25519.pub")
}

resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [format("%s/32", chomp(data.http.icanhazip.response_body))]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_instance" "isucon13" {
  ami                    = "ami-006d211cb716fe8a0"
  instance_type          = "c5.large"
  key_name               = aws_key_pair.deployer.key_name
  vpc_security_group_ids = [aws_security_group.allow_ssh.id]

  root_block_device {
    volume_type = "gp2"
    volume_size = 40
  }

  tags = {
    Name = "isucon13-instance"
  }
}

output "public_ip" {
  value = aws_instance.isucon13.public_ip
}
