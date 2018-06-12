# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2013-12-02"
const awsApiMD_endpointPrefix* = "kinesis"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceAbbreviation* = "Kinesis"
const awsApiMD_serviceFullName* = "Amazon Kinesis"
const awsApiMD_serviceId* = "Kinesis"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "Kinesis_20131202"
const awsApiMD_uid* = "kinesis-2013-12-02"
defineClient(Kinesis)
proc addTagsToStream*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AddTagsToStream", "POST", "/", r)
proc createStream*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateStream", "POST", "/", r)
proc decreaseStreamRetentionPeriod*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DecreaseStreamRetentionPeriod", "POST", "/", r)
proc deleteStream*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteStream", "POST", "/", r)
proc describeLimits*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeLimits", "POST", "/", r)
proc describeStream*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeStream", "POST", "/", r)
proc describeStreamSummary*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeStreamSummary", "POST", "/", r)
proc disableEnhancedMonitoring*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DisableEnhancedMonitoring", "POST", "/", r)
proc enableEnhancedMonitoring*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "EnableEnhancedMonitoring", "POST", "/", r)
proc getRecords*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetRecords", "POST", "/", r)
proc getShardIterator*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetShardIterator", "POST", "/", r)
proc increaseStreamRetentionPeriod*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "IncreaseStreamRetentionPeriod", "POST", "/", r)
proc listStreams*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListStreams", "POST", "/", r)
proc listTagsForStream*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListTagsForStream", "POST", "/", r)
proc mergeShards*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "MergeShards", "POST", "/", r)
proc putRecord*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "PutRecord", "POST", "/", r)
proc putRecords*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "PutRecords", "POST", "/", r)
proc removeTagsFromStream*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "RemoveTagsFromStream", "POST", "/", r)
proc splitShard*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SplitShard", "POST", "/", r)
proc startStreamEncryption*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartStreamEncryption", "POST", "/", r)
proc stopStreamEncryption*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StopStreamEncryption", "POST", "/", r)
proc updateShardCount*(cl: Kinesis, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateShardCount", "POST", "/", r)