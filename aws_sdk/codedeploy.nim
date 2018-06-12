# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2014-10-06"
const awsApiMD_endpointPrefix* = "codedeploy"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceAbbreviation* = "CodeDeploy"
const awsApiMD_serviceFullName* = "AWS CodeDeploy"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "CodeDeploy_20141006"
const awsApiMD_timestampFormat* = "unixTimestamp"
const awsApiMD_uid* = "codedeploy-2014-10-06"
defineClient(CodeDeploy)
proc addTagsToOnPremisesInstances*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AddTagsToOnPremisesInstances", "POST", "/", r)
proc batchGetApplicationRevisions*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchGetApplicationRevisions", "POST", "/", r)
proc batchGetApplications*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchGetApplications", "POST", "/", r)
proc batchGetDeploymentGroups*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchGetDeploymentGroups", "POST", "/", r)
proc batchGetDeploymentInstances*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchGetDeploymentInstances", "POST", "/", r)
proc batchGetDeployments*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchGetDeployments", "POST", "/", r)
proc batchGetOnPremisesInstances*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchGetOnPremisesInstances", "POST", "/", r)
proc continueDeployment*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ContinueDeployment", "POST", "/", r)
proc createApplication*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateApplication", "POST", "/", r)
proc createDeployment*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateDeployment", "POST", "/", r)
proc createDeploymentConfig*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateDeploymentConfig", "POST", "/", r)
proc createDeploymentGroup*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateDeploymentGroup", "POST", "/", r)
proc deleteApplication*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteApplication", "POST", "/", r)
proc deleteDeploymentConfig*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteDeploymentConfig", "POST", "/", r)
proc deleteDeploymentGroup*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteDeploymentGroup", "POST", "/", r)
proc deregisterOnPremisesInstance*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeregisterOnPremisesInstance", "POST", "/", r)
proc getApplication*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetApplication", "POST", "/", r)
proc getApplicationRevision*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetApplicationRevision", "POST", "/", r)
proc getDeployment*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDeployment", "POST", "/", r)
proc getDeploymentConfig*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDeploymentConfig", "POST", "/", r)
proc getDeploymentGroup*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDeploymentGroup", "POST", "/", r)
proc getDeploymentInstance*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDeploymentInstance", "POST", "/", r)
proc getOnPremisesInstance*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetOnPremisesInstance", "POST", "/", r)
proc listApplicationRevisions*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListApplicationRevisions", "POST", "/", r)
proc listApplications*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListApplications", "POST", "/", r)
proc listDeploymentConfigs*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListDeploymentConfigs", "POST", "/", r)
proc listDeploymentGroups*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListDeploymentGroups", "POST", "/", r)
proc listDeploymentInstances*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListDeploymentInstances", "POST", "/", r)
proc listDeployments*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListDeployments", "POST", "/", r)
proc listGitHubAccountTokenNames*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListGitHubAccountTokenNames", "POST", "/", r)
proc listOnPremisesInstances*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListOnPremisesInstances", "POST", "/", r)
proc registerApplicationRevision*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "RegisterApplicationRevision", "POST", "/", r)
proc registerOnPremisesInstance*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "RegisterOnPremisesInstance", "POST", "/", r)
proc removeTagsFromOnPremisesInstances*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "RemoveTagsFromOnPremisesInstances", "POST", "/", r)
proc skipWaitTimeForInstanceTermination*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SkipWaitTimeForInstanceTermination", "POST", "/", r)
proc stopDeployment*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StopDeployment", "POST", "/", r)
proc updateApplication*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateApplication", "POST", "/", r)
proc updateDeploymentGroup*(cl: CodeDeploy, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateDeploymentGroup", "POST", "/", r)
