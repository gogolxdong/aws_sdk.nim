# This file is autogenerated, do not modify
import packedjson, asyncfutures
import utils/client
export client.new
const awsApiMD_apiVersion* = "2015-04-13"
const awsApiMD_endpointPrefix* = "codecommit"
const awsApiMD_jsonVersion* = "1.1"
const awsApiMD_protocol* = "json"
const awsApiMD_serviceAbbreviation* = "CodeCommit"
const awsApiMD_serviceFullName* = "AWS CodeCommit"
const awsApiMD_signatureVersion* = "v4"
const awsApiMD_targetPrefix* = "CodeCommit_20150413"
const awsApiMD_uid* = "codecommit-2015-04-13"
defineClient(CodeCommit)
proc batchGetRepositories*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "BatchGetRepositories", "POST", "/", r)
proc createBranch*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateBranch", "POST", "/", r)
proc createPullRequest*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreatePullRequest", "POST", "/", r)
proc createRepository*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "CreateRepository", "POST", "/", r)
proc deleteBranch*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteBranch", "POST", "/", r)
proc deleteCommentContent*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteCommentContent", "POST", "/", r)
proc deleteRepository*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DeleteRepository", "POST", "/", r)
proc describePullRequestEvents*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "DescribePullRequestEvents", "POST", "/", r)
proc getBlob*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetBlob", "POST", "/", r)
proc getBranch*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetBranch", "POST", "/", r)
proc getComment*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetComment", "POST", "/", r)
proc getCommentsForComparedCommit*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCommentsForComparedCommit", "POST", "/", r)
proc getCommentsForPullRequest*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCommentsForPullRequest", "POST", "/", r)
proc getCommit*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetCommit", "POST", "/", r)
proc getDifferences*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetDifferences", "POST", "/", r)
proc getMergeConflicts*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetMergeConflicts", "POST", "/", r)
proc getPullRequest*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetPullRequest", "POST", "/", r)
proc getRepository*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetRepository", "POST", "/", r)
proc getRepositoryTriggers*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "GetRepositoryTriggers", "POST", "/", r)
proc listBranches*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListBranches", "POST", "/", r)
proc listPullRequests*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListPullRequests", "POST", "/", r)
proc listRepositories*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "ListRepositories", "POST", "/", r)
proc mergePullRequestByFastForward*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "MergePullRequestByFastForward", "POST", "/", r)
proc postCommentForComparedCommit*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "PostCommentForComparedCommit", "POST", "/", r)
proc postCommentForPullRequest*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "PostCommentForPullRequest", "POST", "/", r)
proc postCommentReply*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "PostCommentReply", "POST", "/", r)
proc putRepositoryTriggers*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "PutRepositoryTriggers", "POST", "/", r)
proc testRepositoryTriggers*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "TestRepositoryTriggers", "POST", "/", r)
proc updateComment*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateComment", "POST", "/", r)
proc updateDefaultBranch*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateDefaultBranch", "POST", "/", r)
proc updatePullRequestDescription*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdatePullRequestDescription", "POST", "/", r)
proc updatePullRequestStatus*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdatePullRequestStatus", "POST", "/", r)
proc updatePullRequestTitle*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdatePullRequestTitle", "POST", "/", r)
proc updateRepositoryDescription*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateRepositoryDescription", "POST", "/", r)
proc updateRepositoryName*(cl: CodeCommit, r: JsonNode): Future[JsonNode] = sendJsonRequest(cl, "UpdateRepositoryName", "POST", "/", r)