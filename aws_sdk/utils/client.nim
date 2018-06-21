import json, asyncdispatch, httpclient, times, uri, strtabs,xmlparser,xmltree,strutils,streams,strformat

import ../credentials
import request,xmltojson
import signaturev4
import sph

type
    Client* = ref object of RootObj
        cl: Httpclient
        credentials*: AwsCredentials
        region*: string
        endpoint*: string
        endpointPrefix*: string
        targetPrefix*: string # Target prefix for json protocol
        jsonVersion*: string
        apiVersion*: string
        signingName*: string

template defineClient*(name: untyped) =
    type name* = ref object of Client
    proc fillMetadata*(c: name) =
        c.endpointPrefix = awsApiMD_endpointPrefix
        c.apiVersion = awsApiMD_apiVersion
        when declared(awsApiMD_targetPrefix):
            c.targetPrefix = awsApiMD_targetPrefix
        when declared(awsApiMD_jsonVersion):
            c.jsonVersion = awsApiMD_jsonVersion
        when declared(awsApiMD_signingName):
            c.signingName = awsApiMD_signingName

proc init(c: Client, credentials: AwsCredentials, region: string) =
    c.credentials = credentials
    c.region = region
    c.endpoint = "https://" & c.endpointPrefix & "." & region & ".amazonaws.com/"

proc new*(T: typedesc[Client], credentials: AwsCredentials, region: string = "us-east-1"): T =
    result.new()
    result.fillMetadata()
    result.init(credentials, region)

proc close*(c: Client) =
    if not c.cl.isNil:
        c.cl.close()
        c.cl = nil

proc request*(c: Client, req: AwsRequest, content: string = ""): string =
    var req = req

    const HttpDateFormat = "ddd, dd MMM yyyy HH:mm:ss 'UTC'"
    let time = getTime()

    if "Host" notin req.headers: req.headers["Host"] = req.uri.hostname
    if "Date" notin req.headers and "X-Amz-Date" notin req.headers:
        req.headers["Date"] = format(utc(time), HttpDateFormat)
    var scope = initCredentialScope(req.uri, time)
    if not c.signingName.isNil:
        scope.service = c.signingName
        echo scope.service
    req.headers["Authorization"] = authorizationHeaderv4(c.credentials, scope, req)
    # echo req.headers
    if c.cl.isNil:
        c.cl = newHttpClient()
    for k, v in req.headers:
        if k != "Host":
            c.cl.headers[k] = v

    let resp =  c.cl.request($req.uri, req.httpMethod, body = content)
    result =  resp.body

proc sendJsonRequest*(c: Client, name:string, uri: string, r: JsonNode,  httpMethod = "POST"): JsonNode =
    const HttpDateFormat = "yyyyMMdd'T'HHmmss'Z'"
    let time = getTime()
    let timeStr = format(utc(time), HttpDateFormat)
    let payload = $r
    let payloadHash = sphHash[SHA256](payload)
    let headers = newStringTable({"content-type": "application/x-amz-json-" & c.jsonVersion,"x-amz-target": c.targetPrefix & "." & name,"x-amz-date": timeStr,}, modeCaseInsensitive)
    let req = AwsRequest[StringTableRef](httpMethod: httpMethod,uri: parseUri(c.endpoint),headers: headers,payloadHash: payloadHash)
    let resp =  c.request(req, payload)
    # echo "RESP: ", resp
    result = parseJson(resp)

proc sendEC2Request*(c: Client, name:string, body:JsonNode, uri="", httpMethod="POST"): JsonNode =
    const HttpDateFormat = "yyyyMMdd'T'HHmmss'Z'"
    let time = getTime()
    let timeStr = format(utc(time), HttpDateFormat)
    let payload = ""
    let payloadHash = sphHash[SHA256](payload)
    var headers = newStringTable({"content-type": "application/x-www-form-urlencoded","x-amz-date": timeStr}, modeCaseInsensitive)
    var query = c.endpoint & uri
    echo query
    let req = AwsRequest[StringTableRef](httpMethod: httpMethod,uri: parseUri(query),headers: headers,payloadHash: payloadHash)
    let resp = c.request(req, payload)
    # echo "RESP: ", resp
    result = transform(parseXml(newStringStream resp))

proc sendCWRequest*(c: Client, name:string, uri: string, body:JsonNode, httpMethod="POST"): JsonNode =
    const HttpDateFormat = "yyyyMMdd'T'HHmmss'Z'"
    let timeStr = format(utc getTime(), HttpDateFormat)

    let payload = $body
    let payloadHash = sphHash[SHA256](payload)

    let headers = newStringTable({"content-type": "application/json",
                "x-amz-target": c.targetPrefix & "." & name,"x-amz-date": timeStr,
                "content-encoding" : "amz-1.0"}, modeCaseInsensitive)

    let req = AwsRequest[StringTableRef](httpMethod: httpMethod,uri: parseUri(c.endpoint),headers: headers,payloadHash: payloadHash)

    let resp =  c.request(req, payload)
    result = parseJson(resp)

