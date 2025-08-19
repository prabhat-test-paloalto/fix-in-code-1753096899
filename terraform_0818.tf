provider "aws" {
  region = "ap-south-1" # change as needed
}

resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0" # replace with a valid AMI ID in your region
  instance_type = "t3.micro"

  # Disable IMDSv2 requirement
  metadata_options {
    http_tokens = "required")
  }

  tags = {
    Name      = "siddhant-ec2-fix-in-code-check-2"
    yor_trace = "d8ee6fc5-80d3-4f52-8e7e-9ed25684f8ab"
    yor_name = "sidd-check"
  }
}
