# secure-web-app-cognito

Secure web application example using Amazon Cognito for authentication and authorization, plus DynamoDB for application data storage.

Status: Draft  
Recommended license: MIT

Table of contents
- [About](#about)
- [Features](#features)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Cognito setup (manual)](#cognito-setup-manual)
- [Environment variables](#environment-variables)
- [Examples & SDK notes](#examples--sdk-notes)
- [Infrastructure-as-Code ](#infrastructure-as-code-recommended)
- [Security best practices](#security-best-practices)
- [Testing & CI](#testing--ci)
- [Contributing](#contributing)
- [License](#license)

About
-----
This repository demonstrates a secure pattern for web applications using:
- Amazon Cognito User Pools for user sign-up/sign-in and JWT issuance.
- Cognito Identity Pools for temporary AWS credentials (used when the client directly calls AWS services).
- DynamoDB for application data with least-privilege access patterns.
- Optional server component for token validation and privileged back-end operations.

Use this repo as a starting point to learn and adapt Cognito integration patterns for SPAs, mobile apps, and server-based APIs.

Features
--------
- Step-by-step Cognito setup (User Pool, App Client, Identity Pool).
- Example environment variables and local dev quickstart.
- Guidance on IAM least-privilege for frontend credentials (Identity Pool roles) and server roles.
- Snippets and pointers for verifying Cognito-issued JWTs.
- Recommendations for IaC and CI.

Architecture 
-------------------------
- Frontend (SPA) authenticates users against a Cognito User Pool (OIDC/OpenID Connect).
- After sign-in, the frontend obtains id/access tokens and optionally exchanges them with an Identity Pool for temporary AWS credentials.
- Temporary credentials are used to call AWS services (DynamoDB) directly when appropriate.
- Backend (optional) validates JWTs on each request and performs operations with a server-side role when elevated privileges or data validation are required.

Diagram (text)
Frontend (React/Vue) <--> Cognito User Pool (Auth)  
Frontend (tokens) --> Cognito Identity Pool --> Temporary AWS Credentials --> DynamoDB  
Backend (Node/Express) <--> Validates JWTs or uses server role --> DynamoDB

Quick start
-----------
Prerequisites:
- An AWS account with permission to create Cognito and DynamoDB resources.
- AWS CLI or Console access.
- Node.js >= 16 and npm/yarn if you run the sample frontend/backend.
- (Optional) AWS CDK / Terraform for IaC.

Local quickstart (example)
1. Clone:
   git clone https://github.com/serginhoedouazin13-ui/secure-web-app-cognito.git
   cd secure-web-app-cognito

2. Install dependencies (adjust to actual project layout):
   cd backend && npm install
   cd ../frontend && npm install

3. Create a `.env` (do not commit) with keys like:
   COGNITO_REGION=us-east-1
   COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
   COGNITO_CLIENT_ID=XXXXXXXXXXXXXXXXXXXXXXXXXX
   COGNITO_IDENTITY_POOL_ID=us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   DYNAMODB_TABLE=MyAppTable
   AWS_PROFILE=default

4. Run:
   - Backend: npm run dev (or your start command)
   - Frontend: npm start

Cognito setup (manual)
----------------------
You can either use the Console for a quick setup or automate with IaC (recommended). Manual Console steps:
1. Create a User Pool:
   - Configure attributes (email, etc.), verification, password policy, and MFA as required.
2. Create an App Client:
   - For SPAs: use Authorization Code Grant + PKCE; avoid client secrets in public apps.
   - Configure callback and sign-out URLs.
3. Create an Identity Pool (federated identities):
   - Enable authenticated identities and attach IAM roles for authenticated/unauthenticated users.
4. Map User Pool groups or attributes to Identity Pool roles for role-based access.

Keep these values:
- COGNITO_USER_POOL_ID
- COGNITO_CLIENT_ID
- COGNITO_IDENTITY_POOL_ID
- AWS Region

Environment variables
---------------------
Add a `.env` (gitignored) with values used by frontend/backend. Example:
COGNITO_REGION=us-east-1  
COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX  
COGNITO_CLIENT_ID=XXXXXXXXXXXXXXXXXXXXXXXXXX  
COGNITO_IDENTITY_POOL_ID=us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  
DYNAMODB_TABLE=MyAppTable

Examples & SDK notes
--------------------
- Frontend SDK: Use Authorization Code Grant with PKCE or AWS Amplify (for quick integration).
  Example Amplify config:
  import { Amplify } from "aws-amplify";
  Amplify.configure({
    Auth: {
      region: process.env.COGNITO_REGION,
      userPoolId: process.env.COGNITO_USER_POOL_ID,
      userPoolWebClientId: process.env.COGNITO_CLIENT_ID,
      oauth: { /* callback URLs, scopes */ }
    }
  });

- To get temporary AWS credentials client-side:
  Use AWS SDK v3 credential helpers (e.g., fromCognitoIdentityPool) to obtain credentials scoped to the identity pool.

- JWT validation (backend):
  1. Retrieve JWKS from: https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
  2. Validate signature, issuer, audience (client id), expiry and claims using a JWT/OIDC library.

IAM least-privilege for DynamoDB
--------------------------------
Principles:
- Restrict DynamoDB table ARN and use conditions to scope items to the authenticated user.
- Example policy for an authenticated user (replace region/account/table):
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/MyAppTable",
      "Condition": {
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": ["${cognito-identity.amazonaws.com:sub}"]
        }
      }
    }
  ]
}

Infrastructure-as-Code (recommended)
------------------------------------
Automate resources using one of:
- AWS CDK (TypeScript/Python)
- Terraform
- CloudFormation / SAM

IaC benefits: repeatability, reviewable changes, easier CI/CD. Consider adding a `cdk/` or `terraform/` directory to this repo.

Security best practices
-----------------------
- Use Authorization Code + PKCE for SPAs; avoid client secrets in public clients.
- Validate JWTs on the backend (signature, iss, aud, exp).
- Enforce strong password policies and MFA where appropriate.
- Use short-lived credentials and rotate server-side secrets.
- Do not commit .env or credentials. Use AWS Secrets Manager or Parameter Store for production secrets.
- Apply principle of least privilege for all IAM roles.

Testing and CI
--------------
- Add GitHub Actions to run linting (eslint), tests (Jest/Mocha), and build checks on PRs.
- For integration tests that use AWS, prefer ephemeral test resources provisioned via IaC or use SDK mocks.

Contributing
------------
1. Fork the repo
2. Create a branch: git checkout -b feat/description
3. Commit changes and open a PR with description and testing notes
4. Ensure linters and tests pass

Suggested next additions
- CONTRIBUTING.md and CODE_OF_CONDUCT.md
- .github/ISSUE_TEMPLATE and PULL_REQUEST_TEMPLATE
- GitHub Actions CI workflow
- Example IaC (CDK or Terraform) to provision Cognito + DynamoDB + roles
- Minimal working frontend (React + Amplify) and backend (Node/Express) examples

Contact / Maintainer
--------------------
Maintainer: serginhoedouazin13-ui
