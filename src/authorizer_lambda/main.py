from typing import Any
from authorizer_lambda.config import Settings, config
from authorizer_lambda.models import (
    AuthorizationResponse,
    Owner,
    OwnerResponse,
    TokenAuthorizationRequest,
    OwnerRequest,
    PolicyDocument,
    PolicyStatement,
    StatementEffect
)
import base64
import json

#2nd lambda to retrieve owner_uuid
def invoke(OwnerRequest):
    owner = Owner(first_name="shadek", last_name="rahman", email_address="shadekcse07@gmail.com", phone_number='6754341766', owner_uuid='1234')
    response = OwnerResponse(owner=owner)
    return response
'''
first_name: str
    last_name: str
    email_address: str
    phone_number: str
    owner_uuid: str
'''
def get_owner_uuid(cognito_id: str, settings: Settings) -> str:
    """Retrieve the owner_uuid from the lambda based on the cognito id and return it."""
    request = OwnerRequest(cognito_id=cognito_id)
    # get this from the lambda
    response = invoke(request)
    return response.owner.owner_uuid

def verify_dev_token(token):
    return token

def verify_cognito_token(token):
    return token

def handler(event, context) -> dict[str, Any]:
    """
    Handle the incoming authorization requests, verify the token and return the
    policy for API Gateway
    """

    authorization_request: TokenAuthorizationRequest = (
        TokenAuthorizationRequest.parse_obj(event)
    )
    
    token = authorization_request.authorizationToken
    token_split = token.split('.')
    assert(len(token_split)) == 3
    header, payload, signature = token_split[0], token_split[1], token_split[2]
    
    try:
        payload = base64.b64decode(payload+ '==').decode('utf8')
        payload = json.loads(payload)
        if 'owner_uuid' in payload: # dev token
            verify_dev_token(token)
            principalId = payload['owner_uuid']
            assert(payload['iss']) == 'dev.myapp.ai'
        else:
            sub = payload['sub'] #cognito user id
            verify_cognito_token(token)
            principalId = get_owner_uuid(cognito_id=sub, settings=None)

        policy_statement = PolicyStatement(Effect=StatementEffect.ALLOW, Resource="arn:aws:execute-api:us-east-1:349228585176:aovoxtdoh3/backend_api_gw_stage_dev/*/api/a-b-c-d/*")
    except Exception as e:
        print('exception', e)
        principalId = 'unauthorized'
        policy_statement = PolicyStatement(Effect=StatementEffect.DENY, Resource="arn:aws:execute-api:us-east-1:349228585176:aovoxtdoh3/backend_api_gw_stage_dev/*/api/a-b-c-d/*")

    #policy_statement.Resource = authorization_request.methodArn
    policy_document = PolicyDocument(Statement=[policy_statement])

    authorization_response = AuthorizationResponse(principalId=principalId, policyDocument=policy_document, context={})
    return authorization_response.dict()
