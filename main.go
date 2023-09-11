package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// bash build script: GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -o bootstrap
// PowerShell build script: $env:GOARCH="amd64"; $env:GOOS="linux"; go build -tags lambda.norpc -o bootstrap

// generic function to deserialize the "request" field of the request
func deserialize[M MethodRequest](request Request) (M, PwnyXprsError) {
	var methodRequest M
	err_ := json.Unmarshal(request.Request, &methodRequest)
	if err_ != nil {
		err := err_.Error()
		res := new(M)
		return *res, MalformedRequestError{err}
	}
	return methodRequest, nil
}

func internalHandler(request Request) (Response, PwnyXprsError) {
	// Check if the request parameter matches the actual master password
	initMasterPasswordErr := initMasterPassword(request.Password)
	if initMasterPasswordErr != nil {
		return Response{}, initMasterPasswordErr
	}
	password := request.Password
	if password != *masterPassword {
		return Response{}, AuthError{}
	}

	var err PwnyXprsError
	var resp Response

	switch request.Method {
	case "list":
		var parsedRequest ListRequest
		parsedRequest, err = deserialize[ListRequest](request)
		if err == nil {
			resp, err = handleList(parsedRequest)
		}
	case "get":
		var parsedRequest GetRequest
		parsedRequest, err = deserialize[GetRequest](request)
		if err == nil {
			resp, err = handleGet(parsedRequest, password)
		}
	case "add":
		var parsedRequest AddRequest
		parsedRequest, err = deserialize[AddRequest](request)
		if err == nil {
			resp, err = handleAdd(parsedRequest, password)
		}
	case "update":
		var parsedRequest UpdateRequest
		parsedRequest, err = deserialize[UpdateRequest](request)
		if err == nil {
			resp, err = handleUpdate(parsedRequest, password)
		}
	case "delete":
		var parsedRequest DeleteRequest
		parsedRequest, err = deserialize[DeleteRequest](request)
		if err == nil {
			resp, err = handleDelete(parsedRequest)
		}
	case "export":
		var parsedRequest ExportRequest
		parsedRequest, err = deserialize[ExportRequest](request)
		if err == nil {
			resp, err = handleExport(parsedRequest)
		}
	case "export_plain":
		var parsedRequest ExportPlainRequest
		parsedRequest, err = deserialize[ExportPlainRequest](request)
		if err == nil {
			resp, err = handleExportPlain(parsedRequest, password)
		}
	default:
		return Response{}, MalformedRequestError{"invalid request method"}
	}

	return resp, err
}

func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Validate request
	var request Request
	err_ := json.Unmarshal([]byte(req.Body), &request)
	if err_ != nil {
		err := MalformedRequestError{err_.Error()}
		return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: err.Error()}, nil
	}

	// Check if the request parameter matches the actual master password
	initMasterPasswordErr := initMasterPassword(request.Password)
	if initMasterPasswordErr != nil {
		return events.APIGatewayProxyResponse{StatusCode: initMasterPasswordErr.Status(), Body: initMasterPasswordErr.Error()}, nil
	}

	password := request.Password
	if password != *masterPassword {
		err := AuthError{}
		return events.APIGatewayProxyResponse{StatusCode: err.Status(), Body: err.Error()}, nil
	}

	response, err := internalHandler(request)

	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: err.Status(), Body: err.Error()}, nil
	}

	responseJSON, err_ := json.Marshal(response)
	if err_ != nil {
		json_err := err_.Error()
		err := InternalError{&json_err}
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: err.Error()}, nil
	}

	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK, Body: string(responseJSON)}, nil
}

func main() {
	lambda.Start(handler)
}
