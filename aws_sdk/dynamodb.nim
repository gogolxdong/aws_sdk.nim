# This file is autogenerated, do not modify
import json, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2012-08-10"
const awsApiMD_endpointPrefix* = "dynamodb"
const awsApiMD_jsonVersion* = "1.0"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceAbbreviation* = "DynamoDB"
const awsApiMD_serviceFullName* = "Amazon DynamoDB"
const awsApiMD_serviceId* = "DynamoDB"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "DynamoDB_20120810"
const awsApiMD_uid* = "dynamodb-2012-08-10"
defineClient(DynamoDB)
proc batchGetItem*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchGetItem", "POST", "/", r)
proc batchWriteItem*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchWriteItem", "POST", "/", r)
proc createBackup*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateBackup", "POST", "/", r)
proc createGlobalTable*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateGlobalTable", "POST", "/", r)
proc createTable*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateTable", "POST", "/", r)
proc deleteBackup*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteBackup", "POST", "/", r)
proc deleteItem*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteItem", "POST", "/", r)
proc deleteTable*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteTable", "POST", "/", r)
proc describeBackup*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeBackup", "POST", "/", r)
proc describeContinuousBackups*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeContinuousBackups", "POST", "/", r)
proc describeGlobalTable*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeGlobalTable", "POST", "/", r)
proc describeLimits*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeLimits", "POST", "/", r)
proc describeTable*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeTable", "POST", "/", r)
proc describeTimeToLive*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeTimeToLive", "POST", "/", r)
proc getItem*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetItem", "POST", "/", r)
proc listBackups*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListBackups", "POST", "/", r)
proc listGlobalTables*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListGlobalTables", "POST", "/", r)
proc listTables*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListTables", "POST", "/", r)
proc listTagsOfResource*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListTagsOfResource", "POST", "/", r)
proc putItem*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "PutItem", "POST", "/", r)
proc query*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "Query", "POST", "/", r)
proc restoreTableFromBackup*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "RestoreTableFromBackup", "POST", "/", r)
proc scan*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "Scan", "POST", "/", r)
proc tagResource*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "TagResource", "POST", "/", r)
proc untagResource*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UntagResource", "POST", "/", r)
proc updateGlobalTable*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateGlobalTable", "POST", "/", r)
proc updateItem*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateItem", "POST", "/", r)
proc updateTable*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateTable", "POST", "/", r)
proc updateTimeToLive*(cl: DynamoDB, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateTimeToLive", "POST", "/", r)