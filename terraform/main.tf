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

# variable "win2k8_admin_password" {
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
  description = "Number of kali-ubuntu pairs to generate."
  type = "string"
  default = 1
}

variable "win2k8_private_ip" {
  description = "win2k8 private ip"
  type = "string"
  default = "10.0.0.20"
}

##### output

output "all_the_ips" {
  value = "${formatlist("kali ext, kali int, ubuntu ext, ubuntu int: %s, %s, %s, %s", 
  	aws_instance.kali.*.public_ip,
    aws_instance.kali.*.private_ip,
    aws_instance.ubuntu.*.public_ip,
    aws_instance.ubuntu.*.private_ip)}"
}

output "win2k8" {
  value = "${aws_instance.win2k8.public_ip} ${aws_instance.win2k8.private_ip} ${rsadecrypt(aws_instance.win2k8.password_data, file("${var.ssh_private_key}"))}"
}

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
  private_ip = "10.0.0.${count.index + 10}"
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

  # provisioner "file" {
  #   source      = "ubuntu/xrdp.ini"
  #   destination = "/home/ubuntu/xrdp.ini"
  # }

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
	instance_type = "t2.medium"
	vpc_security_group_ids = ["${aws_security_group.r00tz2018_kali.id}"]
	subnet_id = "${aws_subnet.r00tz2018_subnet.id}"
	private_ip = "10.0.0.${count.index + 110}"
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
  # provisioner "file" {
  #   source      = "ubuntu/xrdp.ini"
  #   destination = "/root/xrdp.ini"
  # }

  provisioner "file" {
    source      = "kali/setup.sh"
    destination = "/home/ec2-user/setup.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod 700 /home/ec2-user/setup.sh",
      "sudo bash /home/ec2-user/setup.sh"
    ]
  }
}

resource "aws_instance" "win2k8" {
  count = 1
  ami = "ami-a2bd89dd"
  instance_type = "t2.medium"
  vpc_security_group_ids = ["${aws_security_group.r00tz2018_win2k8.id}"]
  subnet_id = "${aws_subnet.r00tz2018_subnet.id}"
  key_name = "${aws_key_pair.r00tz2018_key.id}"
  get_password_data = "true"
  private_ip = "${var.win2k8_private_ip}"

  tags {
    Name = "R00TZ2018_WIN2K8"
  }

  # https://www.terraform.io/docs/provisioners/connection.html
  # https://github.com/dhoer/terraform_examples/blob/master/aws-winrm-instance/main.tf
  # connection {
  #   type     = "winrm"
  # }

#   provisioner "remote-exec"  {
#     inline = ["echo hello world"]
#     connection {
#         type = "winrm"
#         user     = "Administrator"
#         password = "${var.win2k8_admin_password}"
#         # password = "${rsadecrypt(aws_instance.win2k8.password_data, file("${var.ssh_private_key}"))}"
#         timeout = "5m"
#     }
#   }

#   user_data = <<EOF
# <script>
#   winrm quickconfig -q & winrm set winrm/config @{MaxTimeoutms="1800000"} & winrm set winrm/config/service @{AllowUnencrypted="true"} & winrm set winrm/config/service/auth @{Basic="true"}
# </script>
# <powershell>
#   netsh advfirewall firewall add rule name="WinRM in" protocol=TCP dir=in profile=any localport=5985 remoteip=any localip=any action=allow
#   # Set Administrator password
#   $admin = [adsi]("WinNT://./administrator, user")
#   $admin.psbase.invoke("SetPassword", "${var.win2k8_admin_password}")
# </powershell>
# EOF

#   user_data = <<EOF
# <powershell>
# $admin = [adsi]("WinNT://./administrator, user")
# $admin.psbase.invoke("SetPassword", "${var.win2k8_admin_password}")
# </powershell>
# EOF
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

resource "aws_security_group" "r00tz2018_win2k8" {
  name = "r00tz2018_win2k8"
  description = "r00tz2018_win2k8"
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
    from_port = 5901
    to_port = 5901
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
    from_port = 5901
    to_port = 5901
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
