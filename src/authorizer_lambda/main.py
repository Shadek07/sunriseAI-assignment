from typing import Any
from authorizer_lambda.config import Settings, config
from authorizer_lambda.models import (
    AuthorizationResponse,
    OwnerResponse,
    TokenAuthorizationRequest,
    OwnerRequest,
    PolicyDocument,
    PolicyStatement,
    StatementEffect
)

import jwt

def get_owner_uuid(cognito_id: str, settings: Settings) -> str:
    """Retrieve the owner_uuid from the lambda based on the cognito id and return it."""
    request = OwnerRequest(cognito_id=cognito_id)
    # get this from the lambda
    response: OwnerResponse
    return response.owner.owner_uuid


def handler(event, context) -> dict[str, Any]:
    """
    Handle the incoming authorization requests, verify the token and return the
    policy for API Gateway
    """

    authorization_request: TokenAuthorizationRequest = (
        TokenAuthorizationRequest.parse_obj(event)
    )
    
    token = authorization_request.authorizationToken
    try:
        decoded_payload = jwt.decode(token, 'secret', algorithms='HS256')
        principalId = decoded_payload['sub']
        policy_statement = PolicyStatement(Effect=StatementEffect.ALLOW)
    except:
        principalId = 'unauthorized'
        policy_statement = PolicyStatement(Effect=StatementEffect.DENY)

    policy_statement.Resource = authorization_request.methodArn
    policy_document = PolicyDocument(Statement=[policy_statement])

    authorization_response = AuthorizationResponse(principalId=principalId, policyDocument=policy_document)
    return authorization_response
