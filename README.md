# Automated Certificate Management using AWS Systems Manager (SSM) for IAM Roles Anywhere

## Description
This project demonstrates an architectural pattern that uses AWS Private Certificate Authority (PCA) and AWS Systems Manager to automate the issuance and renewal of x509 certificates. This process greatly simplifies the integration of on-premises hosts with IAM Roles Anywhere, enhancing security posture and reducing operational complexity.


## Background
IAM Roles Anywhere is a feature that provides a secure and manageable authentication method for applications or systems running outside of AWS. These applications can now exchange x509 certificates for temporary IAM credentials from AWS Security Token Service (STS) to assume an AWS IAM Role.

The architectural pattern proposed by this project allows automated management of these certificates, effectively dealing with the certificate lifecycle. The solution is primarily designed for a Linux environment.

## Architecture
The solution comprises multiple stages involving various AWS services:

1. Amazon EventBridge Scheduler triggers a Lambda function daily.
2. The Lambda function scans an Amazon DynamoDB table to identify instances requiring certificate management.
3. A second Lambda function, triggered based on the certificate's expiry date, instructs Systems Manager to execute a ‘Run Command’ on the instance, generating a Certificate Signing Request (CSR) and a private key.
4. The CSR is retrieved by the Lambda function, and the private key stays securely on the instance.
5. The Lambda function uses the CSR to request a signed certificate from the PCA service.
6. PCA service triggers an event via Amazon EventBridge on successful certificate issuance, which contains the ID of the new certificate.
7. Another Lambda function, triggered by this event, retrieves the certificate from PCA and instructs Systems Manager to execute a ‘Run Command’ with the certificate data.
8. The 'Run Command' tests the certificate's functionality, stores the signed certificate on the instance upon success.
9. The Lambda function updates the certificate's expiry date in the DynamoDB table.

![Diagram](./diagram.png)

## Installation
### Clone the repository
`git@github.com:aws-samples/aws-privateca-certificate-deployment-automator.git`

### Navigate to the cloned repository
`cd aws-privateca-certificate-deployment-automator`

### Run the cloudformation package command
`aws cloudformation package --template-file cf_template.yaml --s3-bucket <bucket_name> --output-template-file packaged.yaml`

### Deploy the CloudFormation stack
`aws cloudformation deploy --template packaged.yaml --stack-name SSM-PCA-Stack --capabilities CAPABILITY_NAMED_IAM --parameter-overrides "CertPath=/tmp" "CACertPath=/tmp" "CSRPath=/tmp" "KeyPath=/tmp"`

After deployment, add the hosts that require certificate management into the DynamoDB table manually.

## Usage
The CertCheck Lambda function created by the CloudFormation template will run daily to ensure the certificates for the hosts are kept up-to-date. If necessary, you can use the AWS cli to run the Lambda function on-demand.
`aws lambda invoke --function-name CertCheck-Trigger --payload '{ "key": "value" }' --cli-binary-format raw-in-base64-out response.json`

## Validation
To validate successful certificate deployment, check the specified location in the CloudFormation parameter. You should find four files: the certificate containing the public key signed by AWS PCA, the certificate chain, the private key for the certificate, and the CSR used to generate the PCA-signed certificate.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

# License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Third Party Libraries

This project uses the [cryptography](https://cryptography.io/en/latest/) library which is licensed under the Apache License, Version 2.0 and the BSD 3-Clause License. The cryptography library and its licensing information can be found at [https://github.com/pyca/cryptography](https://github.com/pyca/cryptography).

### AWS Lambda Layer

The AWS Lambda Layer used in this project includes the cryptography library. This library retains its original licensing, which is the Apache License, Version 2.0 and the BSD 3-Clause License. Please see the respective licenses for more information.



