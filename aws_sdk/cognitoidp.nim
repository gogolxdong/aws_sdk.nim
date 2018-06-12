# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2016-04-18"
const awsApiMD_endpointPrefix* = "cognito-idp"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceFullName* = "Amazon Cognito Identity Provider"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "AWSCognitoIdentityProviderService"
const awsApiMD_uid* = "cognito-idp-2016-04-18"
defineClient(CognitoIDP)
proc addCustomAttributes*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AddCustomAttributes", "POST", "/", r)
proc adminAddUserToGroup*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminAddUserToGroup", "POST", "/", r)
proc adminConfirmSignUp*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminConfirmSignUp", "POST", "/", r)
proc adminCreateUser*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminCreateUser", "POST", "/", r)
proc adminDeleteUser*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminDeleteUser", "POST", "/", r)
proc adminDeleteUserAttributes*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminDeleteUserAttributes", "POST", "/", r)
proc adminDisableProviderForUser*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminDisableProviderForUser", "POST", "/", r)
proc adminDisableUser*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminDisableUser", "POST", "/", r)
proc adminEnableUser*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminEnableUser", "POST", "/", r)
proc adminForgetDevice*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminForgetDevice", "POST", "/", r)
proc adminGetDevice*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminGetDevice", "POST", "/", r)
proc adminGetUser*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminGetUser", "POST", "/", r)
proc adminInitiateAuth*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminInitiateAuth", "POST", "/", r)
proc adminLinkProviderForUser*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminLinkProviderForUser", "POST", "/", r)
proc adminListDevices*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminListDevices", "POST", "/", r)
proc adminListGroupsForUser*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminListGroupsForUser", "POST", "/", r)
proc adminListUserAuthEvents*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminListUserAuthEvents", "POST", "/", r)
proc adminRemoveUserFromGroup*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminRemoveUserFromGroup", "POST", "/", r)
proc adminResetUserPassword*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminResetUserPassword", "POST", "/", r)
proc adminRespondToAuthChallenge*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminRespondToAuthChallenge", "POST", "/", r)
proc adminSetUserMFAPreference*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminSetUserMFAPreference", "POST", "/", r)
proc adminSetUserSettings*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminSetUserSettings", "POST", "/", r)
proc adminUpdateAuthEventFeedback*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminUpdateAuthEventFeedback", "POST", "/", r)
proc adminUpdateDeviceStatus*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminUpdateDeviceStatus", "POST", "/", r)
proc adminUpdateUserAttributes*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminUpdateUserAttributes", "POST", "/", r)
proc adminUserGlobalSignOut*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AdminUserGlobalSignOut", "POST", "/", r)
proc associateSoftwareToken*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AssociateSoftwareToken", "POST", "/", r)
proc changePassword*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ChangePassword", "POST", "/", r)
proc confirmDevice*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ConfirmDevice", "POST", "/", r)
proc confirmForgotPassword*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ConfirmForgotPassword", "POST", "/", r)
proc confirmSignUp*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ConfirmSignUp", "POST", "/", r)
proc createGroup*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateGroup", "POST", "/", r)
proc createIdentityProvider*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateIdentityProvider", "POST", "/", r)
proc createResourceServer*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateResourceServer", "POST", "/", r)
proc createUserImportJob*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateUserImportJob", "POST", "/", r)
proc createUserPool*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateUserPool", "POST", "/", r)
proc createUserPoolClient*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateUserPoolClient", "POST", "/", r)
proc createUserPoolDomain*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateUserPoolDomain", "POST", "/", r)
proc deleteGroup*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteGroup", "POST", "/", r)
proc deleteIdentityProvider*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteIdentityProvider", "POST", "/", r)
proc deleteResourceServer*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteResourceServer", "POST", "/", r)
proc deleteUser*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteUser", "POST", "/", r)
proc deleteUserAttributes*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteUserAttributes", "POST", "/", r)
proc deleteUserPool*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteUserPool", "POST", "/", r)
proc deleteUserPoolClient*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteUserPoolClient", "POST", "/", r)
proc deleteUserPoolDomain*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteUserPoolDomain", "POST", "/", r)
proc describeIdentityProvider*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeIdentityProvider", "POST", "/", r)
proc describeResourceServer*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeResourceServer", "POST", "/", r)
proc describeRiskConfiguration*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeRiskConfiguration", "POST", "/", r)
proc describeUserImportJob*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeUserImportJob", "POST", "/", r)
proc describeUserPool*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeUserPool", "POST", "/", r)
proc describeUserPoolClient*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeUserPoolClient", "POST", "/", r)
proc describeUserPoolDomain*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeUserPoolDomain", "POST", "/", r)
proc forgetDevice*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ForgetDevice", "POST", "/", r)
proc forgotPassword*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ForgotPassword", "POST", "/", r)
proc getCSVHeader*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCSVHeader", "POST", "/", r)
proc getDevice*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDevice", "POST", "/", r)
proc getGroup*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetGroup", "POST", "/", r)
proc getIdentityProviderByIdentifier*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetIdentityProviderByIdentifier", "POST", "/", r)
proc getUICustomization*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetUICustomization", "POST", "/", r)
proc getUser*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetUser", "POST", "/", r)
proc getUserAttributeVerificationCode*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetUserAttributeVerificationCode", "POST", "/", r)
proc getUserPoolMfaConfig*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetUserPoolMfaConfig", "POST", "/", r)
proc globalSignOut*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GlobalSignOut", "POST", "/", r)
proc initiateAuth*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "InitiateAuth", "POST", "/", r)
proc listDevices*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListDevices", "POST", "/", r)
proc listGroups*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListGroups", "POST", "/", r)
proc listIdentityProviders*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListIdentityProviders", "POST", "/", r)
proc listResourceServers*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListResourceServers", "POST", "/", r)
proc listUserImportJobs*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListUserImportJobs", "POST", "/", r)
proc listUserPoolClients*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListUserPoolClients", "POST", "/", r)
proc listUserPools*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListUserPools", "POST", "/", r)
proc listUsers*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListUsers", "POST", "/", r)
proc listUsersInGroup*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListUsersInGroup", "POST", "/", r)
proc resendConfirmationCode*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ResendConfirmationCode", "POST", "/", r)
proc respondToAuthChallenge*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "RespondToAuthChallenge", "POST", "/", r)
proc setRiskConfiguration*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SetRiskConfiguration", "POST", "/", r)
proc setUICustomization*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SetUICustomization", "POST", "/", r)
proc setUserMFAPreference*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SetUserMFAPreference", "POST", "/", r)
proc setUserPoolMfaConfig*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SetUserPoolMfaConfig", "POST", "/", r)
proc setUserSettings*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SetUserSettings", "POST", "/", r)
proc signUp*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SignUp", "POST", "/", r)
proc startUserImportJob*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartUserImportJob", "POST", "/", r)
proc stopUserImportJob*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StopUserImportJob", "POST", "/", r)
proc updateAuthEventFeedback*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateAuthEventFeedback", "POST", "/", r)
proc updateDeviceStatus*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateDeviceStatus", "POST", "/", r)
proc updateGroup*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateGroup", "POST", "/", r)
proc updateIdentityProvider*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateIdentityProvider", "POST", "/", r)
proc updateResourceServer*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateResourceServer", "POST", "/", r)
proc updateUserAttributes*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateUserAttributes", "POST", "/", r)
proc updateUserPool*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateUserPool", "POST", "/", r)
proc updateUserPoolClient*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateUserPoolClient", "POST", "/", r)
proc verifySoftwareToken*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "VerifySoftwareToken", "POST", "/", r)
proc verifyUserAttribute*(cl: CognitoIDP, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "VerifyUserAttribute", "POST", "/", r)