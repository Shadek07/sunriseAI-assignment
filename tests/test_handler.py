from pathlib import Path
import json
from authorizer_lambda import main
from authorizer_lambda.models import (
    AuthorizationResponse,
    PolicyDocument,
    PolicyStatement,
    StatementEffect,
)

'''
      {"alg":"HS256","typ":"JWT"}
      {"iss":"dev.myapp.ai","name":"John Doe","iat":1516239022,"owner_uuid":"a-b-c-d"}
'''

def test_handler(mocker):
    mock_verify_dev_token = mocker.patch.object(main, "verify_dev_token")
    mock_verify_dev_token.return_value = "a-b-c-d"
    request = Path(__file__).parent / Path("data/authorization_request.json")
    request = json.load(request.open("rt"))
    token = request["authorizationToken"]
    response = main.handler(request, {})
    expected = AuthorizationResponse(
        principalId="a-b-c-d",
        policyDocument=PolicyDocument(
            Statement=[
                PolicyStatement(
                    Effect=StatementEffect.ALLOW,
                    Action="execute-api:Invoke",
                    Resource="arn:aws:execute-api:us-east-1:349228585176:aovoxtdoh3/backend_api_gw_stage_dev/*/api/a-b-c-d/*",
                )
            ]
        ),
    ).dict()
    assert response == expected   
    mock_verify_dev_token.assert_called_once_with(token)

#invalid json string: {"iss":"dev.myapp.ai","name":"Shadek","iat":1516239022,"owner_uuid":"a-b-c-d"
def test_unauthorized(mocker):
    request = Path(__file__).parent / Path("data/unauthorized_request.json")
    request = json.load(request.open("rt"))
    response = main.handler(request, {})
    expected = AuthorizationResponse(
        principalId="unauthorized",
        policyDocument=PolicyDocument(
            Statement=[
                PolicyStatement(
                    Effect=StatementEffect.DENY,
                    Action="execute-api:Invoke",
                    Resource="arn:aws:execute-api:us-east-1:349228585176:aovoxtdoh3/backend_api_gw_stage_dev/*/api/a-b-c-d/*",
                )
            ]
        ),
    ).dict()
    assert response == expected  

# {"iss":"aws","name":"Shadek","iat":1516239022,"sub":"user-sub"}
def test_cognito(mocker):
    request = Path(__file__).parent / Path("data/cognito_allow_request.json")
    request = json.load(request.open("rt"))
    response = main.handler(request, {})
    expected = AuthorizationResponse(
        principalId="1234",
        policyDocument=PolicyDocument(
            Statement=[
                PolicyStatement(
                    Effect=StatementEffect.ALLOW,
                    Action="execute-api:Invoke",
                    Resource="arn:aws:execute-api:us-east-1:349228585176:aovoxtdoh3/backend_api_gw_stage_dev/*/api/a-b-c-d/*",
                )
            ]
        ),
    ).dict()
    assert response == expected
