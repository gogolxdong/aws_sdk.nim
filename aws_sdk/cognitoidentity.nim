# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2014-06-30"
const awsApiMD_endpointPrefix* = "cognito-identity"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceFullName* = "Amazon Cognito Identity"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "AWSCognitoIdentityService"
const awsApiMD_uid* = "cognito-identity-2014-06-30"
defineClient(CognitoIdentity)
proc createIdentityPool*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateIdentityPool", "POST", "/", r)
proc deleteIdentities*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteIdentities", "POST", "/", r)
proc deleteIdentityPool*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteIdentityPool", "POST", "/", r)
proc describeIdentity*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeIdentity", "POST", "/", r)
proc describeIdentityPool*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeIdentityPool", "POST", "/", r)
proc getCredentialsForIdentity*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCredentialsForIdentity", "POST", "/", r)
proc getId*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetId", "POST", "/", r)
proc getIdentityPoolRoles*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetIdentityPoolRoles", "POST", "/", r)
proc getOpenIdToken*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetOpenIdToken", "POST", "/", r)
proc getOpenIdTokenForDeveloperIdentity*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetOpenIdTokenForDeveloperIdentity", "POST", "/", r)
proc listIdentities*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListIdentities", "POST", "/", r)
proc listIdentityPools*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListIdentityPools", "POST", "/", r)
proc lookupDeveloperIdentity*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "LookupDeveloperIdentity", "POST", "/", r)
proc mergeDeveloperIdentities*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "MergeDeveloperIdentities", "POST", "/", r)
proc setIdentityPoolRoles*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SetIdentityPoolRoles", "POST", "/", r)
proc unlinkDeveloperIdentity*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UnlinkDeveloperIdentity", "POST", "/", r)
proc unlinkIdentity*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UnlinkIdentity", "POST", "/", r)
proc updateIdentityPool*(cl: CognitoIdentity, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateIdentityPool", "POST", "/", r)
