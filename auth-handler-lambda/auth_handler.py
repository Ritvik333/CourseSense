import json
import boto3
import os
import time
from botocore.exceptions import ClientError

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('SessionStore')
cognito = boto3.client('cognito-idp')

def lambda_handler(event, context):
    try:
        body = json.loads(event['body'])
        action = body.get('action', 'login')
        user_pool_id = os.environ['COGNITO_USER_POOL_ID']
        client_id = os.environ['COGNITO_CLIENT_ID']

        if action == 'register':
            role = body.get('role', 'student')  # Default to student
            response = cognito.sign_up(
                ClientId=client_id,
                Username=body['email'],
                Password=body['password'],
                UserAttributes=[{'Name': 'email', 'Value': body['email']}, {'Name': 'custom:role', 'Value': role}]
            )
            return {
                'statusCode': 200,
                'body': json.dumps('Registration successful. Verify your email.')
            }

        elif action == 'login':
            # Initiate authentication with Cognito
            response = cognito.initiate_auth(
                ClientId=client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={'USERNAME': body['email'], 'PASSWORD': body['password']}
            )
            
            # Handle MFA challenge if required
            if 'ChallengeName' in response and response['ChallengeName'] == 'SOFTWARE_TOKEN_MFA':
                return {
                    'statusCode': 401,
                    'body': json.dumps({
                        'message': 'MFA required',
                        'session': response['Session']  # Pass session for MFA step
                    })
                }

            # Authentication successful, get ID token
            id_token = response['AuthenticationResult']['IdToken']
            session_id = body['email'] + '_' + str(time.time())

            # Get user attributes to determine role
            user_attr = cognito.get_user(AccessToken=response['AuthenticationResult']['AccessToken'])
            role = next((attr['Value'] for attr in user_attr['UserAttributes'] if attr['Name'] == 'custom:role'), 'student')

            # Store session in DynamoDB
            table.put_item(
                Item={
                    'SessionId': session_id,
                    'Token': id_token,
                    'Expiry': int(time.time()) + 3600,  # 1-hour expiry
                    'Email': body['email'],
                    'Role': role
                }
            )

            return {
                'statusCode': 200,
                'body': json.dumps({'token': id_token, 'sessionId': session_id, 'role': role})
            }

        elif action == 'mfa':
            # Verify MFA code
            response = cognito.respond_to_auth_challenge(
                ClientId=client_id,
                ChallengeName='SOFTWARE_TOKEN_MFA',
                Session=body.get('session'),  # Session from login response
                ChallengeResponses={'SOFTWARE_TOKEN_MFA_CODE': body['mfa_code']}
            )

            # Authentication successful after MFA
            id_token = response['AuthenticationResult']['IdToken']
            session_id = body['email'] + '_' + str(time.time())

            # Get user attributes to determine role
            user_attr = cognito.get_user(AccessToken=response['AuthenticationResult']['AccessToken'])
            role = next((attr['Value'] for attr in user_attr['UserAttributes'] if attr['Name'] == 'custom:role'), 'student')

            # Store session in DynamoDB
            table.put_item(
                Item={
                    'SessionId': session_id,
                    'Token': id_token,
                    'Expiry': int(time.time()) + 3600,
                    'Email': body['email'],
                    'Role': role
                }
            )

            return {
                'statusCode': 200,
                'body': json.dumps({'token': id_token, 'sessionId': session_id, 'role': role})
            }

        elif action == 'logout':
            session_id = body.get('sessionId')
            if session_id:
                table.delete_item(Key={'SessionId': session_id})
            return {
                'statusCode': 200,
                'body': json.dumps('Logged out successfully')
            }

        return {
            'statusCode': 400,
            'body': json.dumps('Invalid action')
        }

    except ClientError as e:
        print(f"Error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error: {e.response['Error']['Message']}")
        }