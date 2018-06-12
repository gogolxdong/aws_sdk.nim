# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2017-07-24"
const awsApiMD_endpointPrefix* = "sagemaker"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceAbbreviation* = "SageMaker"
const awsApiMD_serviceFullName* = "Amazon SageMaker Service"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_signingName* = "sagemaker"
const awsApiMD_targetPrefix* = "SageMaker"
const awsApiMD_uid* = "sagemaker-2017-07-24"
defineClient(SageMaker)
proc addTags*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "AddTags", "POST", "/", r)
proc createEndpoint*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateEndpoint", "POST", "/", r)
proc createEndpointConfig*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateEndpointConfig", "POST", "/", r)
proc createModel*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateModel", "POST", "/", r)
proc createNotebookInstance*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateNotebookInstance", "POST", "/", r)
proc createPresignedNotebookInstanceUrl*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreatePresignedNotebookInstanceUrl", "POST", "/", r)
proc createTrainingJob*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateTrainingJob", "POST", "/", r)
proc deleteEndpoint*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteEndpoint", "POST", "/", r)
proc deleteEndpointConfig*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteEndpointConfig", "POST", "/", r)
proc deleteModel*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteModel", "POST", "/", r)
proc deleteNotebookInstance*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteNotebookInstance", "POST", "/", r)
proc deleteTags*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteTags", "POST", "/", r)
proc describeEndpoint*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeEndpoint", "POST", "/", r)
proc describeEndpointConfig*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeEndpointConfig", "POST", "/", r)
proc describeModel*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeModel", "POST", "/", r)
proc describeNotebookInstance*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeNotebookInstance", "POST", "/", r)
proc describeTrainingJob*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribeTrainingJob", "POST", "/", r)
proc listEndpointConfigs*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListEndpointConfigs", "POST", "/", r)
proc listEndpoints*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListEndpoints", "POST", "/", r)
proc listModels*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListModels", "POST", "/", r)
proc listNotebookInstances*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListNotebookInstances", "POST", "/", r)
proc listTags*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListTags", "POST", "/", r)
proc listTrainingJobs*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListTrainingJobs", "POST", "/", r)
proc startNotebookInstance*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StartNotebookInstance", "POST", "/", r)
proc stopNotebookInstance*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StopNotebookInstance", "POST", "/", r)
proc stopTrainingJob*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "StopTrainingJob", "POST", "/", r)
proc updateEndpoint*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateEndpoint", "POST", "/", r)
proc updateEndpointWeightsAndCapacities*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateEndpointWeightsAndCapacities", "POST", "/", r)
proc updateNotebookInstance*(cl: SageMaker, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateNotebookInstance", "POST", "/", r)