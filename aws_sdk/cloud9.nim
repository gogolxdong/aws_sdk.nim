# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2017-09-23"
const awsApiMD_endpointPrefix* = "cloud9"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceFullName* = "AWS Cloud9"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "AWSCloud9WorkspaceManagementService"
const awsApiMD_uid* = "cloud9-2017-09-23"
defineClient(Cloud9)
proc createEnvironmentEC2*(cl: Cloud9, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateEnvironmentEC2", "POST", "/", r)
proc createEnvironmentMembership*(cl: Cloud9, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateEnvironmentMembership", "POST", "/", r)
proc deleteEnvironment*(cl: Cloud9, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteEnvironment", "POST", "/", r)
proc deleteEnvironmentMembership*(cl: Cloud9, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteEnvironmentMembership", "POST", "/", r)
proc describeEnvironmentMemberships*(cl: Cloud9, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeEnvironmentMemberships", "POST", "/", r)
proc describeEnvironmentStatus*(cl: Cloud9, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeEnvironmentStatus", "POST", "/", r)
proc describeEnvironments*(cl: Cloud9, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeEnvironments", "POST", "/", r)
proc listEnvironments*(cl: Cloud9, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListEnvironments", "POST", "/", r)
proc updateEnvironment*(cl: Cloud9, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateEnvironment", "POST", "/", r)
proc updateEnvironmentMembership*(cl: Cloud9, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateEnvironmentMembership", "POST", "/", r)