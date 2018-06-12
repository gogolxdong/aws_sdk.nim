# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2016-08-04"
const awsApiMD_endpointPrefix* = "health"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceAbbreviation* = "AWSHealth"
const awsApiMD_serviceFullName* = "AWS Health APIs and Notifications"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "AWSHealth_20160804"
const awsApiMD_uid* = "health-2016-08-04"
defineClient(Health)
proc describeAffectedEntities*(cl: Health, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeAffectedEntities", "POST", "/", r)
proc describeEntityAggregates*(cl: Health, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeEntityAggregates", "POST", "/", r)
proc describeEventAggregates*(cl: Health, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeEventAggregates", "POST", "/", r)
proc describeEventDetails*(cl: Health, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeEventDetails", "POST", "/", r)
proc describeEventTypes*(cl: Health, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeEventTypes", "POST", "/", r)
proc describeEvents*(cl: Health, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeEvents", "POST", "/", r)
