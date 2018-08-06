##### variables

variable "aws_region" {
  description = "AWS region."
  type = "string"
}

variable "aws_access_key" {
  description = "AWS access key."
  type = "string"
}

variable "aws_secret_key" {
  description = "AWS secret key."
  type = "string"
}

# variable "win_admin_password" {
#   description = "Windows admin password."
#   type = "string"
# }

variable "kali_user_password" {
  description = "Password for users on Kali boxes."
  type = "string"
}

variable "ssh_public_key" {
  description = "public SSH key for admin on all boxes."
  type = "string"
}

variable "ssh_private_key" {
  description = "private SSH key for admin on all boxes."
  type = "string"
}

variable "num_boxes" {
  description = "Number of kali-windows pairs to generate."
  type = "string"
  default = 1
}

##### output

# output "all_the_ips" {
#   value = "${formatlist("ubuntu ext, ubuntu int: %s, %s, %s, %s", 
#     aws_instance.ubuntu.*.public_ip,
#     aws_instance.ubuntu.*.private_ip)}"
# }

output "all_the_ips" {
  value = "${formatlist("kali ext, kali int, ubuntu ext, ubuntu int: %s, %s, %s, %s", 
  	aws_instance.kali.*.public_ip,
    aws_instance.kali.*.private_ip,
    aws_instance.ubuntu.*.public_ip,
    aws_instance.ubuntu.*.private_ip)}"
    # aws_instance.win2k8.*.public_ip,
    # aws_instance.win2k8.*.private_ip)}"
}

# output "connect_cmd" {
#   value = "rdesktop -g 1600x900 -u Administrator -x l ${aws_instance.purgenol_win2k8r2.public_ip}"
# }

##### providers

provider "aws" {
	region = "us-east-1"
	access_key = "${var.aws_access_key}"
	secret_key = "${var.aws_secret_key}"
}

resource "aws_instance" "ubuntu" {
  # username: r00tz2018
  # kali 2018.1
  ami = "ami-b04847cf"
  instance_type = "t2.medium"
  vpc_security_group_ids = ["${aws_security_group.r00tz2018_ubuntu.id}"]
  subnet_id = "${aws_subnet.r00tz2018_subnet.id}"
  private_ip = "10.0.0.${count.index + 110}"
  count = "${var.num_boxes}"
  key_name = "${aws_key_pair.r00tz2018_key.id}"
  # private_ip = "10.0.1.${lookup(var.private_ips, count.index) + 10}"

  tags {
    Name = "R00TZ2018_UBUNTU_${count.index}"
  }

  connection {
    type = "ssh"
    user = "ubuntu"
    private_key = "${file("${var.ssh_private_key}")}"
  }

  provisioner "file" {
    source      = "ubuntu/setup.sh"
    destination = "/home/ubuntu/setup.sh"
  }

  provisioner "file" {
    source      = "ubuntu/nginx.conf"
    destination = "/home/ubuntu/nginx.conf"
  }

  provisioner "file" {
    source      = "ubuntu/xrdp.ini"
    destination = "/home/ubuntu/xrdp.ini"
  }

  provisioner "file" {
    source      = "ubuntu/drupal-pewpewkittens.sql"
    destination = "/home/ubuntu/drupal-pewpewkittens.sql"
  }

  provisioner "file" {
    source      = "ubuntu/drupal-pewpewkittens.tar.gz"
    destination = "/home/ubuntu/drupal-pewpewkittens.tar.gz"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod 700 /home/ubuntu/setup.sh",
      "sudo bash /home/ubuntu/setup.sh"
    ]
  }
}

# https://aws.amazon.com/marketplace/fulfillment?productId=8b7fdfe3-8cd5-43cc-8e5e-4e0e7f4139d5&ref_=dtl_psb_continue&region=us-east-1
resource "aws_instance" "kali" {
	# kali 2018.1
	ami = "ami-10e00b6d"
	instance_type = "t2.small"
	vpc_security_group_ids = ["${aws_security_group.r00tz2018_kali.id}"]
	subnet_id = "${aws_subnet.r00tz2018_subnet.id}"
	private_ip = "10.0.0.${count.index + 10}"
	count = "${var.num_boxes}"
	key_name = "${aws_key_pair.r00tz2018_key.id}"
	# private_ip = "10.0.1.${lookup(var.private_ips, count.index) + 10}"

	tags {
		Name = "R00TZ2018_KALI_${count.index}"
	}

  connection {
    type = "ssh"
    user = "ec2-user"
    private_key = "${file("${var.ssh_private_key}")}"
  }

  provisioner "remote-exec" {
    inline = [
      # "sudo su",
      "(echo \"${var.kali_user_password}\"; echo \"${var.kali_user_password}\") | sudo passwd ec2-user",
      # "sudo apt install ftp -y",
      # "sudo sed -i '1s@^@covfefeinthemorning\\n@' /usr/share/wordlists/rockyou.txt",
      "sudo sed -i '/PasswordAuthentication/d' /etc/ssh/sshd_config",
      # "useradd r00tz2018",
      # "(echo \"${var.kali_user_password}\"; echo \"${var.kali_user_password}\") | passwd r00tz2018",
      "sudo bash -c \"echo \"PasswordAuthentication yes\" >> /etc/ssh/sshd_config\"",
      "sudo systemctl restart sshd"
    ]
  }
}

# https://www.terraform.io/docs/providers/aws/r/vpc.html
resource "aws_vpc" "r00tz2018_vpc" {
	cidr_block       = "10.0.0.0/24"
	instance_tenancy = "default"

	tags {
		Name = "r00tz2018_vpc"
	}
}

resource "aws_key_pair" "r00tz2018_key" {
	key_name   = "r00tz2018_key"
	public_key = "${file("${var.ssh_public_key}")}"
}

# https://www.terraform.io/docs/providers/aws/r/internet_gateway.html
resource "aws_internet_gateway" "r00tz2018_ig" {
	vpc_id = "${aws_vpc.r00tz2018_vpc.id}"
}

resource "aws_security_group" "r00tz2018_ubuntu" {
  name = "r00tz2018_ubuntu"
  description = "r00tz2018_ubuntu"
  vpc_id = "${aws_vpc.r00tz2018_vpc.id}"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 0
    to_port = 0
    protocol = -1
    cidr_blocks = ["10.0.0.0/24"]
  }

  ingress {
    from_port = 3389
    to_port = 3389
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  } 

  egress {
    from_port = 0
    to_port = 0
    protocol = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "r00tz2018_kali" {
	name = "r00tz2018_kali"
	description = "r00tz2018_kali"
	vpc_id = "${aws_vpc.r00tz2018_vpc.id}"
	ingress {
		from_port = 22
		to_port = 22
		protocol = "tcp"
		cidr_blocks = ["0.0.0.0/0"]
	}

	ingress {
		from_port = 0
		to_port = 0
		protocol = -1
		cidr_blocks = ["10.0.0.0/24"]
	}

	ingress {
		from_port = 3389
		to_port = 3389
		protocol = "tcp"
		cidr_blocks = ["0.0.0.0/0"]
	}	

	egress {
		from_port = 0
		to_port = 0
		protocol = -1
		cidr_blocks = ["0.0.0.0/0"]
	}
}

# https://www.terraform.io/docs/providers/aws/d/subnet.html
resource "aws_subnet" "r00tz2018_subnet" {
	vpc_id = "${aws_vpc.r00tz2018_vpc.id}"
	cidr_block = "10.0.0.0/24"
	map_public_ip_on_launch = true
}

resource "aws_route" "internet_access" {
	route_table_id = "${aws_vpc.r00tz2018_vpc.main_route_table_id}"
	gateway_id = "${aws_internet_gateway.r00tz2018_ig.id}"
	destination_cidr_block = "0.0.0.0/0"
}
