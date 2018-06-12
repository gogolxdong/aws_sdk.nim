# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2017-11-27"
const awsApiMD_endpointPrefix* = "comprehend"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceFullName* = "Amazon Comprehend"
const awsApiMD_serviceId* = "Comprehend"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_signingName* = "comprehend"
const awsApiMD_targetPrefix* = "Comprehend_20171127"
const awsApiMD_uid* = "comprehend-2017-11-27"
defineClient(Comprehend)
proc batchDetectDominantLanguage*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchDetectDominantLanguage", "POST", "/", r)
proc batchDetectEntities*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchDetectEntities", "POST", "/", r)
proc batchDetectKeyPhrases*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchDetectKeyPhrases", "POST", "/", r)
proc batchDetectSentiment*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchDetectSentiment", "POST", "/", r)
proc describeTopicsDetectionJob*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeTopicsDetectionJob", "POST", "/", r)
proc detectDominantLanguage*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DetectDominantLanguage", "POST", "/", r)
proc detectEntities*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DetectEntities", "POST", "/", r)
proc detectKeyPhrases*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DetectKeyPhrases", "POST", "/", r)
proc detectSentiment*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DetectSentiment", "POST", "/", r)
proc listTopicsDetectionJobs*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListTopicsDetectionJobs", "POST", "/", r)
proc startTopicsDetectionJob*(cl: Comprehend, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartTopicsDetectionJob", "POST", "/", r)
