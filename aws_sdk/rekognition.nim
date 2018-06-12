# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2016-06-27"
const awsApiMD_endpointPrefix* = "rekognition"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceFullName* = "Amazon Rekognition"
const awsApiMD_serviceId* = "Rekognition"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "RekognitionService"
const awsApiMD_uid* = "rekognition-2016-06-27"
defineClient(Rekognition)
proc compareFaces*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CompareFaces", "POST", "/", r)
proc createCollection*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateCollection", "POST", "/", r)
proc createStreamProcessor*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateStreamProcessor", "POST", "/", r)
proc deleteCollection*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteCollection", "POST", "/", r)
proc deleteFaces*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteFaces", "POST", "/", r)
proc deleteStreamProcessor*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteStreamProcessor", "POST", "/", r)
proc describeStreamProcessor*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeStreamProcessor", "POST", "/", r)
proc detectFaces*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DetectFaces", "POST", "/", r)
proc detectLabels*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DetectLabels", "POST", "/", r)
proc detectModerationLabels*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DetectModerationLabels", "POST", "/", r)
proc detectText*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DetectText", "POST", "/", r)
proc getCelebrityInfo*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCelebrityInfo", "POST", "/", r)
proc getCelebrityRecognition*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCelebrityRecognition", "POST", "/", r)
proc getContentModeration*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetContentModeration", "POST", "/", r)
proc getFaceDetection*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetFaceDetection", "POST", "/", r)
proc getFaceSearch*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetFaceSearch", "POST", "/", r)
proc getLabelDetection*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetLabelDetection", "POST", "/", r)
proc getPersonTracking*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetPersonTracking", "POST", "/", r)
proc indexFaces*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "IndexFaces", "POST", "/", r)
proc listCollections*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListCollections", "POST", "/", r)
proc listFaces*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListFaces", "POST", "/", r)
proc listStreamProcessors*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListStreamProcessors", "POST", "/", r)
proc recognizeCelebrities*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "RecognizeCelebrities", "POST", "/", r)
proc searchFaces*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SearchFaces", "POST", "/", r)
proc searchFacesByImage*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "SearchFacesByImage", "POST", "/", r)
proc startCelebrityRecognition*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartCelebrityRecognition", "POST", "/", r)
proc startContentModeration*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartContentModeration", "POST", "/", r)
proc startFaceDetection*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartFaceDetection", "POST", "/", r)
proc startFaceSearch*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartFaceSearch", "POST", "/", r)
proc startLabelDetection*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartLabelDetection", "POST", "/", r)
proc startPersonTracking*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartPersonTracking", "POST", "/", r)
proc startStreamProcessor*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartStreamProcessor", "POST", "/", r)
proc stopStreamProcessor*(cl: Rekognition, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StopStreamProcessor", "POST", "/", r)