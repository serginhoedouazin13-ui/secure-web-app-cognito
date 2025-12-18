# secure-web-app-cognito
Secure web application using Amazon Cognito for user authentication and authorization. Includes user pool setup, identity pool configuration, and DynamoDB access

AWS Services Used:
Amazon Cognito User Pools – User authentication and management

Amazon Cognito Identity Pools – Authorization and temporary AWS credentials

AWS IAM – Role-based access control and least privilege

Amazon DynamoDB – Secure backend data storage

Amazon S3 (optional) – Static web hosting

Security Features:

Secure user sign-up and sign-in using Amazon Cognito

Token-based authentication (JWT)

Temporary AWS credentials via STS (no hard-coded credentials)

IAM roles scoped to minimum required permissions

Separation of authentication (User Pool) and authorization (Identity Pool)

Setup Instructions:
1️. Create Cognito User Pool

Configure sign-in options (email/username)

Set password policy

Create users or enable self sign-up

2️. Configure Identity Pool
Link Identity Pool to the User Pool
Enable authenticated identities
Attach IAM role for authenticated users

3️. IAM Role Configuration
Grant least-privilege access to DynamoDB

4. Application Configuration
Update app with User Pool ID and App Client ID
Configure Identity Pool ID
Test authentication and DynamoDB access

Testing:
Verify user sign-up and login

Confirm JWT tokens are issued
Validate DynamoDB access only works for authenticated users
Test access denial for unauthenticated users
