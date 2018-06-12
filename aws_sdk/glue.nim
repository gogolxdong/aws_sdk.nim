# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2017-03-31"
const awsApiMD_endpointPrefix* = "glue"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceFullName* = "AWS Glue"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "AWSGlue"
const awsApiMD_uid* = "glue-2017-03-31"
defineClient(Glue)
proc batchCreatePartition*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchCreatePartition", "POST", "/", r)
proc batchDeleteConnection*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchDeleteConnection", "POST", "/", r)
proc batchDeletePartition*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchDeletePartition", "POST", "/", r)
proc batchDeleteTable*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchDeleteTable", "POST", "/", r)
proc batchGetPartition*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchGetPartition", "POST", "/", r)
proc batchStopJobRun*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchStopJobRun", "POST", "/", r)
proc createClassifier*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateClassifier", "POST", "/", r)
proc createConnection*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateConnection", "POST", "/", r)
proc createCrawler*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateCrawler", "POST", "/", r)
proc createDatabase*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateDatabase", "POST", "/", r)
proc createDevEndpoint*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateDevEndpoint", "POST", "/", r)
proc createJob*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateJob", "POST", "/", r)
proc createPartition*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreatePartition", "POST", "/", r)
proc createScript*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateScript", "POST", "/", r)
proc createTable*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateTable", "POST", "/", r)
proc createTrigger*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateTrigger", "POST", "/", r)
proc createUserDefinedFunction*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateUserDefinedFunction", "POST", "/", r)
proc deleteClassifier*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteClassifier", "POST", "/", r)
proc deleteConnection*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteConnection", "POST", "/", r)
proc deleteCrawler*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteCrawler", "POST", "/", r)
proc deleteDatabase*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteDatabase", "POST", "/", r)
proc deleteDevEndpoint*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteDevEndpoint", "POST", "/", r)
proc deleteJob*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteJob", "POST", "/", r)
proc deletePartition*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeletePartition", "POST", "/", r)
proc deleteTable*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteTable", "POST", "/", r)
proc deleteTrigger*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteTrigger", "POST", "/", r)
proc deleteUserDefinedFunction*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteUserDefinedFunction", "POST", "/", r)
proc getCatalogImportStatus*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCatalogImportStatus", "POST", "/", r)
proc getClassifier*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetClassifier", "POST", "/", r)
proc getClassifiers*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetClassifiers", "POST", "/", r)
proc getConnection*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetConnection", "POST", "/", r)
proc getConnections*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetConnections", "POST", "/", r)
proc getCrawler*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCrawler", "POST", "/", r)
proc getCrawlerMetrics*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCrawlerMetrics", "POST", "/", r)
proc getCrawlers*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCrawlers", "POST", "/", r)
proc getDatabase*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDatabase", "POST", "/", r)
proc getDatabases*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDatabases", "POST", "/", r)
proc getDataflowGraph*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDataflowGraph", "POST", "/", r)
proc getDevEndpoint*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDevEndpoint", "POST", "/", r)
proc getDevEndpoints*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDevEndpoints", "POST", "/", r)
proc getJob*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetJob", "POST", "/", r)
proc getJobRun*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetJobRun", "POST", "/", r)
proc getJobRuns*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetJobRuns", "POST", "/", r)
proc getJobs*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetJobs", "POST", "/", r)
proc getMapping*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetMapping", "POST", "/", r)
proc getPartition*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetPartition", "POST", "/", r)
proc getPartitions*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetPartitions", "POST", "/", r)
proc getPlan*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetPlan", "POST", "/", r)
proc getTable*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetTable", "POST", "/", r)
proc getTableVersions*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetTableVersions", "POST", "/", r)
proc getTables*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetTables", "POST", "/", r)
proc getTrigger*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetTrigger", "POST", "/", r)
proc getTriggers*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetTriggers", "POST", "/", r)
proc getUserDefinedFunction*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetUserDefinedFunction", "POST", "/", r)
proc getUserDefinedFunctions*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetUserDefinedFunctions", "POST", "/", r)
proc importCatalogToGlue*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ImportCatalogToGlue", "POST", "/", r)
proc resetJobBookmark*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ResetJobBookmark", "POST", "/", r)
proc startCrawler*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartCrawler", "POST", "/", r)
proc startCrawlerSchedule*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartCrawlerSchedule", "POST", "/", r)
proc startJobRun*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartJobRun", "POST", "/", r)
proc startTrigger*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartTrigger", "POST", "/", r)
proc stopCrawler*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StopCrawler", "POST", "/", r)
proc stopCrawlerSchedule*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StopCrawlerSchedule", "POST", "/", r)
proc stopTrigger*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StopTrigger", "POST", "/", r)
proc updateClassifier*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateClassifier", "POST", "/", r)
proc updateConnection*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateConnection", "POST", "/", r)
proc updateCrawler*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateCrawler", "POST", "/", r)
proc updateCrawlerSchedule*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateCrawlerSchedule", "POST", "/", r)
proc updateDatabase*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateDatabase", "POST", "/", r)
proc updateDevEndpoint*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateDevEndpoint", "POST", "/", r)
proc updateJob*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateJob", "POST", "/", r)
proc updatePartition*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdatePartition", "POST", "/", r)
proc updateTable*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateTable", "POST", "/", r)
proc updateTrigger*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateTrigger", "POST", "/", r)
proc updateUserDefinedFunction*(cl: Glue, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateUserDefinedFunction", "POST", "/", r)
