# Secure Web Application with Amazon Cognito 

[![Tests](https://github.com/serginhoedouazin13-ui/secure-web-app-cognito/workflows/Python%20Tests/badge.svg)](https://github.com/serginhoedouazin13-ui/secure-web-app-cognito/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![AWS](https://img.shields.io/badge/AWS-Cognito-orange.svg)](https://aws.amazon.com/cognito/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Production-ready secure web application using Amazon Cognito for user authentication and authorization. Features complete user pool setup, identity pool configuration, and secure DynamoDB access with fine-grained permissions.

##  Features

-  **Complete Authentication**: Sign up, sign in, password reset, email verification
-  **User Pool Management**: AWS Cognito User Pool with custom attributes
-  **Identity Federation**: Identity Pool for AWS resource access
-  **DynamoDB Integration**: Secure database access with IAM roles
-  **Token Management**: JWT token validation and refresh
-  **Authorization**: Role-based access control (RBAC)
-  **Email Verification**: SES integration for user verification
-  **Password Policies**: Configurable password strength requirements
-  **MFA Support**: Multi-factor authentication with TOTP
-  **OAuth 2.0**: Social login (Google, Facebook, Amazon)

##  Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [AWS Setup](#aws-setup)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Deployment](#deployment)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)


### Authentication Flow

1. **User Registration**
   - User submits credentials → Cognito User Pool
   - Verification email sent → User confirms
   - User account activated

2. **User Sign-In**
   - User provides credentials → Cognito validates
   - JWT tokens issued (ID, Access, Refresh)
   - Tokens used for subsequent requests

3. **AWS Resource Access**
   - Exchange Cognito token → Identity Pool
   - Temporary AWS credentials issued
   - Access DynamoDB, S3, etc. with IAM role

##  Prerequisites

- **AWS Account**: Active AWS account with appropriate permissions
- **Python**: 3.9 or higher
- **AWS CLI**: Configured with credentials ([Install AWS CLI](https://aws.amazon.com/cli/))
- **Node.js**: 14+ (for frontend, if applicable)
- **Git**: For cloning the repository

##  AWS Setup

### 1. Create Cognito User Pool

Using AWS Console:

1. Navigate to **Amazon Cognito** → **User Pools** → **Create user pool**
2. Configure sign-in options:
   - ✅ Email
   - ✅ Username (optional)
3. Configure password policies:
   - Minimum length: 8 characters
   - Require: Uppercase, lowercase, numbers, special characters
4. Configure MFA (optional but recommended):
   - Optional or Required
   - TOTP or SMS
5. Configure email delivery:
   - Use Amazon SES or Cognito email

### Using AWS CLI:

```bash
# Create User Pool
aws cognito-idp create-user-pool \
  --pool-name SecureAppUserPool \
  --policies '{
    "PasswordPolicy": {
      "MinimumLength": 8,
      "RequireUppercase": true,
      "RequireLowercase": true,
      "RequireNumbers": true,
      "RequireSymbols": true
    }
  }' \
  --auto-verified-attributes email \
  --username-attributes email \
  --schema '[
    {
      "Name": "email",
      "Required": true,
      "Mutable": false
    }
  ]'

# Create User Pool Client
aws cognito-idp create-user-pool-client \
  --user-pool-id <YOUR_USER_POOL_ID> \
  --client-name SecureAppClient \
  --generate-secret \
  --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH
```

### Using CloudFormation:

```yaml
# cloudformation/cognito-stack.yml
Resources:
  UserPool:
    Type: AWS::Cognito::UserPool
    Properties:
      UserPoolName: SecureAppUserPool
      AutoVerifiedAttributes:
        - email
      UsernameAttributes:
        - email
      Policies:
        PasswordPolicy:
          MinimumLength: 8
          RequireUppercase: true
          RequireLowercase: true
          RequireNumbers: true
          RequireSymbols: true
      Schema:
        - Name: email
          Required: true
          Mutable: false
        - Name: name
          Required: true
          Mutable: true
      EmailConfiguration:
        EmailSendingAccount: COGNITO_DEFAULT

  UserPoolClient:
    Type: AWS::Cognito::UserPoolClient
    Properties:
      ClientName: SecureAppClient
      UserPoolId: !Ref UserPool
      GenerateSecret: true
      ExplicitAuthFlows:
        - ALLOW_USER_PASSWORD_AUTH
        - ALLOW_REFRESH_TOKEN_AUTH
      PreventUserExistenceErrors: ENABLED

  IdentityPool:
    Type: AWS::Cognito::IdentityPool
    Properties:
      IdentityPoolName: SecureAppIdentityPool
      AllowUnauthenticatedIdentities: false
      CognitoIdentityProviders:
        - ClientId: !Ref UserPoolClient
          ProviderName: !GetAtt UserPool.ProviderName

  # IAM Roles for authenticated users
  AuthenticatedRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: cognito-identity.amazonaws.com
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                cognito-identity.amazonaws.com:aud: !Ref IdentityPool
              ForAnyValue:StringLike:
                cognito-identity.amazonaws.com:amr: authenticated
      Policies:
        - PolicyName: AuthenticatedPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - dynamodb:GetItem
                  - dynamodb:PutItem
                  - dynamodb:UpdateItem
                  - dynamodb:Query
                Resource: !GetAtt UsersTable.Arn

  UsersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: Users
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: userId
          AttributeType: S
      KeySchema:
        - AttributeName: userId
          KeyType: HASH
```

Deploy the stack:
```bash
aws cloudformation create-stack \
  --stack-name secure-app-cognito \
  --template-body file://cloudformation/cognito-stack.yml \
  --capabilities CAPABILITY_IAM
```

### 2. Create DynamoDB Tables

```bash
# Users table
aws dynamodb create-table \
  --table-name Users \
  --attribute-definitions \
    AttributeName=userId,AttributeType=S \
  --key-schema \
    AttributeName=userId,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# User sessions table (optional)
aws dynamodb create-table \
  --table-name UserSessions \
  --attribute-definitions \
    AttributeName=sessionId,AttributeType=S \
  --key-schema \
    AttributeName=sessionId,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### 3. Configure IAM Roles

See the CloudFormation template above for complete IAM role configuration.

## 📦 Installation

### Backend Setup

```bash
# Clone the repository
git clone https://github.com/serginhoedouazin13-ui/secure-web-app-cognito.git
cd secure-web-app-cognito

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Frontend Setup (if applicable)

```bash
cd frontend
npm install
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# AWS Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key

# Cognito User Pool
COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
COGNITO_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Cognito Identity Pool
COGNITO_IDENTITY_POOL_ID=us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# DynamoDB
DYNAMODB_USERS_TABLE=Users
DYNAMODB_SESSIONS_TABLE=UserSessions

# Application
APP_ENV=development
APP_SECRET_KEY=your-secret-key-here
DEBUG=true
LOG_LEVEL=INFO

# Security
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000
SESSION_TIMEOUT=3600
TOKEN_EXPIRY=3600

# Email (SES)
SES_EMAIL_SOURCE=noreply@yourdomain.com
SES_REGION=us-east-1
```

### Configuration File

Create `config/settings.py`:

```python
import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    # AWS
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    
    # Cognito
    cognito_user_pool_id: str = os.getenv("COGNITO_USER_POOL_ID")
    cognito_client_id: str = os.getenv("COGNITO_CLIENT_ID")
    cognito_client_secret: str = os.getenv("COGNITO_CLIENT_SECRET")
    cognito_identity_pool_id: str = os.getenv("COGNITO_IDENTITY_POOL_ID")
    
    # DynamoDB
    dynamodb_users_table: str = os.getenv("DYNAMODB_USERS_TABLE", "Users")
    dynamodb_sessions_table: str = os.getenv("DYNAMODB_SESSIONS_TABLE", "UserSessions")
    
    # Application
    app_env: str = os.getenv("APP_ENV", "development")
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    class Config:
        env_file = ".env"

settings = Settings()
```

##  Usage

### Starting the Application

```bash
# Development mode
python app/main.py

# Or with uvicorn (for FastAPI)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### User Registration

```python
import boto3
from botocore.exceptions import ClientError

client = boto3.client('cognito-idp', region_name='us-east-1')

def sign_up(username, password, email):
    try:
        response = client.sign_up(
            ClientId='YOUR_CLIENT_ID',
            Username=username,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email}
            ]
        )
        return response
    except ClientError as e:
        print(f"Error: {e}")
        return None

# Example usage
sign_up('john.doe', 'SecurePassword123!', 'john@example.com')
```

### Email Verification

```python
def confirm_sign_up(username, confirmation_code):
    try:
        response = client.confirm_sign_up(
            ClientId='YOUR_CLIENT_ID',
            Username=username,
            ConfirmationCode=confirmation_code
        )
        return response
    except ClientError as e:
        print(f"Error: {e}")
        return None
```

### User Sign-In

```python
import hmac
import hashlib
import base64

def get_secret_hash(username, client_id, client_secret):
    message = bytes(username + client_id, 'utf-8')
    secret = bytes(client_secret, 'utf-8')
    dig = hmac.new(secret, msg=message, digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

def sign_in(username, password, client_id, client_secret):
    secret_hash = get_secret_hash(username, client_id, client_secret)
    
    try:
        response = client.initiate_auth(
            ClientId=client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )
        return response['AuthenticationResult']
    except ClientError as e:
        print(f"Error: {e}")
        return None

# Example usage
tokens = sign_in('john.doe', 'SecurePassword123!', 'YOUR_CLIENT_ID', 'YOUR_CLIENT_SECRET')
# Returns: {'IdToken': '...', 'AccessToken': '...', 'RefreshToken': '...'}
```

### Token Refresh

```python
def refresh_token(refresh_token, client_id, client_secret, username):
    secret_hash = get_secret_hash(username, client_id, client_secret)
    
    try:
        response = client.initiate_auth(
            ClientId=client_id,
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': refresh_token,
                'SECRET_HASH': secret_hash
            }
        )
        return response['AuthenticationResult']
    except ClientError as e:
        print(f"Error: {e}")
        return None
```

### Accessing DynamoDB with Cognito Credentials

```python
from boto3.session import Session
from warrant import Cognito

def get_aws_credentials(id_token):
    """Exchange Cognito token for AWS credentials"""
    identity_client = boto3.client('cognito-identity', region_name='us-east-1')
    
    # Get identity ID
    identity_response = identity_client.get_id(
        IdentityPoolId='YOUR_IDENTITY_POOL_ID',
        Logins={
            f'cognito-idp.us-east-1.amazonaws.com/YOUR_USER_POOL_ID': id_token
        }
    )
    
    # Get credentials
    credentials_response = identity_client.get_credentials_for_identity(
        IdentityId=identity_response['IdentityId'],
        Logins={
            f'cognito-idp.us-east-1.amazonaws.com/YOUR_USER_POOL_ID': id_token
        }
    )
    
    return credentials_response['Credentials']

def access_dynamodb(id_token):
    """Access DynamoDB using Cognito credentials"""
    credentials = get_aws_credentials(id_token)
    
    # Create session with temporary credentials
    session = Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    # Access DynamoDB
    dynamodb = session.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('Users')
    
    # Perform operations
    response = table.get_item(Key={'userId': 'user123'})
    return response.get('Item')
```

##  API Documentation

### Authentication Endpoints

#### POST /api/auth/signup
Register a new user.

**Request:**
```json
{
  "username": "john.doe",
  "password": "SecurePassword123!",
  "email": "john@example.com",
  "name": "John Doe"
}
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user_sub": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "confirmation_required": true
}
```

#### POST /api/auth/confirm
Confirm user email with verification code.

**Request:**
```json
{
  "username": "john.doe",
  "confirmation_code": "123456"
}
```

**Response:**
```json
{
  "message": "Email confirmed successfully"
}
```

#### POST /api/auth/signin
Sign in and get JWT tokens.

**Request:**
```json
{
  "username": "john.doe",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "id_token": "eyJraWQiOiJ...",
  "access_token": "eyJraWQiOiJ...",
  "refresh_token": "eyJjdHkiOiJ...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

#### POST /api/auth/refresh
Refresh access token.

**Request:**
```json
{
  "refresh_token": "eyJjdHkiOiJ..."
}
```

**Response:**
```json
{
  "id_token": "eyJraWQiOiJ...",
  "access_token": "eyJraWQiOiJ...",
  "expires_in": 3600
}
```

#### POST /api/auth/signout
Sign out user.

**Request:**
```json
{
  "access_token": "eyJraWQiOiJ..."
}
```

**Response:**
```json
{
  "message": "User signed out successfully"
}
```

#### POST /api/auth/forgot-password
Initiate password reset.

**Request:**
```json
{
  "username": "john.doe"
}
```

**Response:**
```json
{
  "message": "Password reset code sent to email"
}
```

#### POST /api/auth/reset-password
Reset password with confirmation code.

**Request:**
```json
{
  "username": "john.doe",
  "confirmation_code": "123456",
  "new_password": "NewSecurePassword123!"
}
```

**Response:**
```json
{
  "message": "Password reset successfully"
}
```

### User Management Endpoints

#### GET /api/users/me
Get current user profile (requires authentication).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "user_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "username": "john.doe",
  "email": "john@example.com",
  "name": "John Doe",
  "email_verified": true,
  "created_at": "2024-02-03T10:30:00Z"
}
```

#### PUT /api/users/me
Update user profile.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
  "name": "John Updated Doe",
  "phone_number": "+1234567890"
}
```

**Response:**
```json
{
  "message": "Profile updated successfully",
  "user": {
    "name": "John Updated Doe",
    "phone_number": "+1234567890"
  }
}
```

#### DELETE /api/users/me
Delete user account.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Account deleted successfully"
}
```

### Protected Resource Endpoints

#### GET /api/data
Access protected data (requires authentication).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "data": [
    {"id": 1, "value": "Protected data item 1"},
    {"id": 2, "value": "Protected data item 2"}
  ]
}
```

##  Testing

### Test Structure

```
tests/
├── unit/
│   ├── test_auth.py           # Authentication tests
│   ├── test_token.py          # Token validation tests
│   ├── test_user_mgmt.py      # User management tests
│   └── test_dynamodb.py       # DynamoDB operations tests
├── integration/
│   ├── test_auth_flow.py      # End-to-end auth flow
│   └── test_api.py            # API endpoint tests
├── fixtures/
│   └── cognito_fixtures.py    # Mock Cognito responses
└── conftest.py                # Pytest configuration
```

### Running Tests

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html --cov-report=term

# Run specific test file
pytest tests/unit/test_auth.py -v

# Run with mocked AWS services (using moto)
pytest tests/unit/ -v

# Run integration tests (requires AWS credentials)
pytest tests/integration/ -v
```

### Example Test

```python
# tests/unit/test_auth.py
import pytest
from moto import mock_cognitoidp
import boto3
from app.services.auth import AuthService

@mock_cognitoidp
def test_user_signup():
    # Setup mock Cognito
    client = boto3.client('cognito-idp', region_name='us-east-1')
    
    # Create mock user pool
    user_pool = client.create_user_pool(PoolName='TestPool')
    pool_id = user_pool['UserPool']['Id']
    
    # Create mock client
    app_client = client.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName='TestClient'
    )
    client_id = app_client['UserPoolClient']['ClientId']
    
    # Test signup
    auth_service = AuthService(pool_id, client_id)
    response = auth_service.sign_up(
        username='testuser',
        password='TestPassword123!',
        email='test@example.com'
    )
    
    assert response is not None
    assert 'UserSub' in response

@pytest.fixture
def mock_tokens():
    return {
        'IdToken': 'mock_id_token',
        'AccessToken': 'mock_access_token',
        'RefreshToken': 'mock_refresh_token'
    }

def test_token_validation(mock_tokens):
    # Test token validation logic
    pass
```

### GitHub Actions CI/CD

`.github/workflows/tests.yml`:

```yaml
name: Python Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        python-version: ['3.9', '3.10', '3.11', '3.12']
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v5
      with:
        python-version: ${{ matrix.python-version }}
        cache: 'pip'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
    
    - name: Run tests with moto (mocked AWS)
      run: |
        pytest tests/unit/ --cov=app --cov-report=xml -v
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v4
      with:
        file: ./coverage.xml
        flags: unittests
        name: codecov-umbrella
    
    - name: Lint with flake8
      run: |
        flake8 app/ --count --select=E9,F63,F7,F82 --show-source --statistics
    
    - name: Check code formatting with black
      run: |
        black --check app/
    
    - name: Type check with mypy
      run: |
        mypy app/
```

##  Deployment

### Docker Deployment

#### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/
COPY config/ ./config/

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### Docker Compose

```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - AWS_REGION=${AWS_REGION}
      - COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID}
      - COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID}
      - COGNITO_CLIENT_SECRET=${COGNITO_CLIENT_SECRET}
      - COGNITO_IDENTITY_POOL_ID=${COGNITO_IDENTITY_POOL_ID}
    env_file:
      - .env
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

**Deploy:**
```bash
docker-compose up -d
```

### AWS Elastic Beanstalk

```bash
# Initialize EB
eb init -p python-3.11 secure-web-app

# Create environment
eb create production-env

# Deploy
eb deploy

# Open application
eb open
```

### AWS Lambda + API Gateway

Using Serverless Framework:

```yaml
# serverless.yml
service: secure-web-app-cognito

provider:
  name: aws
  runtime: python3.11
  region: us-east-1
  environment:
    COGNITO_USER_POOL_ID: ${env:COGNITO_USER_POOL_ID}
    COGNITO_CLIENT_ID: ${env:COGNITO_CLIENT_ID}
    DYNAMODB_USERS_TABLE: ${self:custom.usersTableName}
  
  iamRoleStatements:
    - Effect: Allow
      Action:
        - dynamodb:Query
        - dynamodb:GetItem
        - dynamodb:PutItem
        - dynamodb:UpdateItem
        - dynamodb:DeleteItem
      Resource:
        - "arn:aws:dynamodb:${self:provider.region}:*:table/${self:custom.usersTableName}"

custom:
  usersTableName: Users

functions:
  auth:
    handler: app.handlers.auth_handler
    events:
      - http:
          path: /api/auth/{proxy+}
          method: ANY
          cors: true
  
  users:
    handler: app.handlers.users_handler
    events:
      - http:
          path: /api/users/{proxy+}
          method: ANY
          cors: true
          authorizer:
            type: COGNITO_USER_POOLS
            authorizerId:
              Ref: ApiGatewayAuthorizer

resources:
  Resources:
    ApiGatewayAuthorizer:
      Type: AWS::ApiGateway::Authorizer
      Properties:
        Name: CognitoAuthorizer
        Type: COGNITO_USER_POOLS
        IdentitySource: method.request.header.Authorization
        RestApiId:
          Ref: ApiGatewayRestApi
        ProviderARNs:
          - arn:aws:cognito-idp:${self:provider.region}:${aws:accountId}:userpool/${env:COGNITO_USER_POOL_ID}
```

**Deploy:**
```bash
serverless deploy --stage production
```

##  Security Best Practices

### 1. Password Policies

Enforce strong passwords in Cognito:
- Minimum length: 8 characters
- Require uppercase, lowercase, numbers, and symbols
- Prevent password reuse
- Set password expiration (optional)

### 2. Multi-Factor Authentication (MFA)

Enable MFA for sensitive operations:

```python
def enable_mfa(access_token):
    client.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={
            'Enabled': True,
            'PreferredMfa': True
        }
    )
```

### 3. Token Security

- Store tokens securely (httpOnly cookies, secure storage)
- Implement token rotation
- Use short-lived access tokens (1 hour)
- Validate tokens on every request
- Implement token blacklisting for logout

```python
import jwt
from jwt import PyJWKClient

def validate_token(token, user_pool_id, region):
    keys_url = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'
    jwks_client = PyJWKClient(keys_url)
    
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],
            options={'verify_exp': True}
        )
        return decoded
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")
```

### 4. IAM Least Privilege

Grant minimal permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:*:table/Users",
      "Condition": {
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": ["${cognito-identity.amazonaws.com:sub}"]
        }
      }
    }
  ]
}
```

### 5. HTTPS Only

Always use HTTPS in production:
- Enable SSL/TLS certificates
- Redirect HTTP to HTTPS
- Use HSTS headers

### 6. Rate Limiting

Implement rate limiting to prevent abuse:

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/auth/signin")
@limiter.limit("5/minute")
async def signin(request: Request):
    # Sign in logic
    pass
```

### 7. Input Validation

Validate all inputs:

```python
from pydantic import BaseModel, EmailStr, validator

class SignUpRequest(BaseModel):
    username: str
    password: str
    email: EmailStr
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain lowercase')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain numbers')
        return v
```

### 8. Logging and Monitoring

Monitor authentication events:

```python
import logging

logger = logging.getLogger(__name__)

def log_auth_event(event_type, username, success, ip_address):
    logger.info(f"Auth Event: {event_type} | User: {username} | Success: {success} | IP: {ip_address}")
    
    # Send to CloudWatch Logs
    # Trigger alerts on suspicious activity
```

### 9. CORS Configuration

Configure CORS properly:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Specific origins only
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

### 10. Security Headers

Add security headers:

```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)
```

##  Troubleshooting

### Common Issues

#### 1. "NotAuthorizedException: Incorrect username or password"

**Causes:**
- Wrong credentials
- User not confirmed
- User disabled

**Solution:**
```python
# Check user status
response = client.admin_get_user(
    UserPoolId='YOUR_USER_POOL_ID',
    Username='username'
)
print(response['UserStatus'])  # Should be 'CONFIRMED'
```

#### 2. "InvalidParameterException: Cannot verify provided TOTP code"

**Cause:** Wrong MFA code or clock skew

**Solution:**
- Ensure device time is synchronized
- Check TOTP time step (usually 30 seconds)

#### 3. "User pool client YOUR_CLIENT_ID does not have a secret"

**Cause:** Client app not configured with secret

**Solution:**
```bash
# Recreate client with secret
aws cognito-idp create-user-pool-client \
  --user-pool-id YOUR_USER_POOL_ID \
  --client-name NewClient \
  --generate-secret
```

#### 4. "NotAuthorizedException: Invalid Refresh Token"

**Cause:** Token expired or revoked

**Solution:**
- Check token expiration
- Re-authenticate user
- Check if refresh token auth flow is enabled

#### 5. "AccessDeniedException" when accessing DynamoDB

**Cause:** IAM role permissions insufficient

**Solution:**
```json
{
  "Effect": "Allow",
  "Action": [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
    "dynamodb:Query"
  ],
  "Resource": "arn:aws:dynamodb:*:*:table/YourTable"
}
```

#### 6. "User does not exist" after signup

**Cause:** Email not verified

**Solution:**
```python
# Resend confirmation code
client.resend_confirmation_code(
    ClientId='YOUR_CLIENT_ID',
    Username='username'
)
```

### Debug Mode

Enable debug logging:

```python
import logging
import boto3

# Enable boto3 debug logging
boto3.set_stream_logger('boto3.resources', logging.DEBUG)

# Enable application debug
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
```

### Testing Cognito Locally

Use LocalStack for local development:

```bash
# Start LocalStack
docker run -d -p 4566:4566 localstack/localstack

# Configure boto3 to use LocalStack
client = boto3.client(
    'cognito-idp',
    endpoint_url='http://localhost:4566',
    region_name='us-east-1'
)
```

##  Additional Resources

- [AWS Cognito Documentation](https://docs.aws.amazon.com/cognito/)
- [Boto3 Cognito Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html)
- [JWT Token Validation](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html)
- [Cognito Security Best Practices](https://docs.aws.amazon.com/cognito/latest/developerguide/managing-security.html)

##  Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR-USERNAME/secure-web-app-cognito.git
cd secure-web-app-cognito

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
pytest
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Acknowledgments

- AWS Cognito team for excellent authentication services
- FastAPI community for the amazing framework
- Contributors and maintainers

##  Support

-  [Documentation](docs/)
-  [Report Issues](https://github.com/serginhoedouazin13-ui/secure-web-app-cognito/issues)
-  [Discussions](https://github.com/serginhoedouazin13-ui/secure-web-app-cognito/discussions)

---

**Built with 🔐 by [Your Name]**

[Documentation](docs/) | [API Reference](docs/API.md) | [Security](docs/SECURITY.md) | [Contributing](CONTRIBUTING.md)
