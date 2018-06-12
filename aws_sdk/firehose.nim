# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2015-08-04"
const awsApiMD_endpointPrefix* = "firehose"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceAbbreviation* = "Firehose"
const awsApiMD_serviceFullName* = "Amazon Kinesis Firehose"
const awsApiMD_serviceId* = "Firehose"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "Firehose_20150804"
const awsApiMD_uid* = "firehose-2015-08-04"
defineClient(Firehose)
proc createDeliveryStream*(cl: Firehose, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateDeliveryStream", "POST", "/", r)
proc deleteDeliveryStream*(cl: Firehose, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteDeliveryStream", "POST", "/", r)
proc describeDeliveryStream*(cl: Firehose, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeDeliveryStream", "POST", "/", r)
proc listDeliveryStreams*(cl: Firehose, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListDeliveryStreams", "POST", "/", r)
proc putRecord*(cl: Firehose, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "PutRecord", "POST", "/", r)
proc putRecordBatch*(cl: Firehose, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "PutRecordBatch", "POST", "/", r)
proc updateDestination*(cl: Firehose, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateDestination", "POST", "/", r)
