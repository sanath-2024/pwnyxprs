package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws/awserr"
)

var bucketName = os.Getenv("PW_BUCKET")
var masterPasswordObjectName = os.Getenv("MASTER_PW_OBJECT")
var masterPassword *string

func initMasterPassword(testMasterPassword string) PwnyXprsError {
	if masterPassword != nil {
		return nil
	}

	verifyPW, verifyPWError := handleGet(GetRequest{Name: masterPasswordObjectName}, testMasterPassword)

	if verifyPWError != nil {
		return verifyPWError
	}

	if testMasterPassword != verifyPW.Get.Val {
		return AuthError{}
	}

	masterPassword = &testMasterPassword
	return nil
}

// multiplexed request type
// request types:
// list (list all passwords)
// get (get a specific password)
// add (add a new password)
// update (update an existing password)
// delete (delete an existing password)
// export (export all passwords in encrypted form)
// export_plain (export all passwords in plaintext form)
type Request struct {
	Method   string          `json:"method"`
	Password string          `json:"password"`
	Request  json.RawMessage `json:"request"`
}

type MethodRequest interface {
	isMethodRequest()
}

type ListRequest struct{}
type ListResponse struct {
	Passwords []string `json:"passwords"`
}

func (r ListRequest) isMethodRequest() {}

type GetRequest struct {
	Name string `json:"name"`
}
type GetResponse struct {
	Val string `json:"val"`
}

func (r GetRequest) isMethodRequest() {}

type AddRequest struct {
	Name string `json:"name"`
	Val  string `json:"val"`
}
type AddResponse struct{}

func (r AddRequest) isMethodRequest() {}

type UpdateRequest struct {
	Name string `json:"name"`
	Val  string `json:"val"`
}
type UpdateResponse struct{}

func (r UpdateRequest) isMethodRequest() {}

type DeleteRequest struct {
	Name string `json:"name"`
}
type DeleteResponse struct{}

func (r DeleteRequest) isMethodRequest() {}

type ExportRequest struct{}
type ExportResponse struct {
	Passwords map[string][]byte `json:"passwords"`
}

func (r ExportRequest) isMethodRequest() {}

type ExportPlainRequest struct{}
type ExportPlainResponse struct {
	Passwords map[string]string `json:"passwords"`
}

func (r ExportPlainRequest) isMethodRequest() {}

type Response struct {
	List        *ListResponse        `json:"list,omitempty"`
	Get         *GetResponse         `json:"get,omitempty"`
	Add         *AddResponse         `json:"add,omitempty"`
	Update      *UpdateResponse      `json:"update,omitempty"`
	Delete      *DeleteResponse      `json:"delete,omitempty"`
	Export      *ExportResponse      `json:"export,omitempty"`
	ExportPlain *ExportPlainResponse `json:"export_plain,omitempty"`
}

func initClient() *s3.Client {
	var cfg, err_ = config.LoadDefaultConfig(context.TODO())
	if err_ != nil {
		return nil
	}
	return s3.NewFromConfig(cfg)
}

var client = initClient()

func handleList(req ListRequest) (Response, PwnyXprsError) {
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	}

	var objectNames []string

	paginator := s3.NewListObjectsV2Paginator(client, input)
	for paginator.HasMorePages() {
		page, err_ := paginator.NextPage(context.TODO())
		if err_ != nil {
			err := err_.Error()
			return Response{}, InternalError{&err}
		}

		for _, obj := range page.Contents {
			objectNames = append(objectNames, *obj.Key)
		}
	}

	return Response{List: &ListResponse{objectNames}}, nil
}

func getObject(objectName string) ([]byte, PwnyXprsError) {
	if len(objectName) == 0 {
		return nil, MalformedRequestError{"name cannot be empty"}
	}
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
	}

	output, err_ := client.GetObject(context.Background(), input)
	if err_ != nil {
		err := err_.Error()
		return nil, InternalError{&err}
	}

	defer output.Body.Close()

	password, err_ := io.ReadAll(output.Body)

	if err_ != nil {
		err := err_.Error()
		return nil, InternalError{&err}
	}

	return password, nil
}

func handleGet(req GetRequest, masterPW string) (Response, PwnyXprsError) {
	password, err := getObject(req.Name)
	if err != nil {
		return Response{}, err
	}

	decryptedPassword, err := decrypt(password, masterPW)

	if err != nil {
		return Response{}, err
	}

	return Response{Get: &GetResponse{decryptedPassword}}, nil
}

func doesObjectExist(objectName string) (bool, PwnyXprsError) {
	if len(objectName) == 0 {
		return false, MalformedRequestError{"name cannot be empty"}
	}
	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
	}

	_, err_ := client.HeadObject(context.Background(), input)

	if err_ != nil {
		// Check if the error is NoSuchKey, indicating that the object does not exist.
		if aerr, ok := err_.(awserr.Error); ok && aerr.Code() == "NoSuchKey" {
			return false, nil
		}
		err := err_.Error()
		return false, InternalError{&err}
	}

	return true, nil
}

func handleAdd(req AddRequest, masterPW string) (Response, PwnyXprsError) {
	// add a new object, only if it doesn't already exist
	if len(req.Name) == 0 {
		return Response{}, MalformedRequestError{"name cannot be empty"}
	}
	exists, err := doesObjectExist(req.Name)
	if err != nil {
		return Response{}, err
	}
	if exists {
		err := "object already exists"
		return Response{}, InternalError{&err}
	}

	encryptedPassword, err := encrypt(req.Val, masterPW)

	if err != nil {
		return Response{}, err
	}

	input := &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(req.Name),
		Body:   bytes.NewReader(encryptedPassword),
	}

	_, err_ := client.PutObject(context.Background(), input)
	if err_ != nil {
		err := err_.Error()
		return Response{}, InternalError{&err}
	}

	return Response{Add: &AddResponse{}}, nil
}

func handleUpdate(req UpdateRequest, masterPW string) (Response, PwnyXprsError) {
	// update an existing object, only if it already exists
	if len(req.Name) == 0 {
		return Response{}, MalformedRequestError{"name cannot be empty"}
	}
	if req.Name == masterPasswordObjectName {
		err := "cannot update master password"
		return Response{}, InternalError{&err}
	}

	exists, err := doesObjectExist(req.Name)
	if err != nil {
		return Response{}, err
	}
	if !exists {
		err := "object does not exist"
		return Response{}, InternalError{&err}
	}

	encryptedPassword, err := encrypt(req.Val, masterPW)

	if err != nil {
		return Response{}, err
	}

	input := &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(req.Name),
		Body:   bytes.NewReader(encryptedPassword),
	}

	_, err_ := client.PutObject(context.Background(), input)
	if err_ != nil {
		err := err_.Error()
		return Response{}, InternalError{&err}
	}

	return Response{Update: &UpdateResponse{}}, nil
}

func handleDelete(req DeleteRequest) (Response, PwnyXprsError) {
	// delete an existing object, only if it already exists
	if len(req.Name) == 0 {
		return Response{}, MalformedRequestError{"name cannot be empty"}
	}
	if req.Name == masterPasswordObjectName {
		err := "cannot delete master password"
		return Response{}, InternalError{&err}
	}

	exists, err := doesObjectExist(req.Name)
	if err != nil {
		return Response{}, err
	}
	if !exists {
		err := "object does not exist"
		return Response{}, InternalError{&err}
	}

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(req.Name),
	}

	_, err_ := client.DeleteObject(context.Background(), input)
	if err_ != nil {
		err := err_.Error()
		return Response{}, InternalError{&err}
	}

	return Response{Delete: &DeleteResponse{}}, nil
}

func handleExport(req ExportRequest) (Response, PwnyXprsError) {
	// call into handleList to get all object names
	listResponse, listError := handleList(ListRequest{})

	if listError != nil {
		return Response{}, listError
	}

	// concurrently call into getObject for each object name
	// and store the results in a map
	type PwResp struct {
		err_       PwnyXprsError
		objectName string
		password   []byte
	}
	pw_chan := make(chan PwResp, len(listResponse.List.Passwords))
	for _, objectName := range listResponse.List.Passwords {
		go func(objectName string) {
			getResponse, getError := getObject(objectName)
			if getError == nil {
				pw_chan <- PwResp{nil, objectName, getResponse}
			} else {
				pw_chan <- PwResp{getError, objectName, []byte{}}
			}
		}(objectName)
	}

	// put all responses into a map
	passwords := make(map[string][]byte)
	for range listResponse.List.Passwords {
		pw_resp := <-pw_chan
		if pw_resp.err_ != nil {
			return Response{}, pw_resp.err_
		}
		passwords[pw_resp.objectName] = pw_resp.password
	}

	return Response{Export: &ExportResponse{passwords}}, nil
}

func handleExportPlain(req ExportPlainRequest, masterPW string) (Response, PwnyXprsError) {
	// call into handleList to get all object names
	listResponse, listError := handleList(ListRequest{})

	if listError != nil {
		return Response{}, listError
	}

	// concurrently call into handleGet for each object name
	// and store the results in a map
	type PwResp struct {
		err_       PwnyXprsError
		objectName string
		password   string
	}
	pw_chan := make(chan PwResp, len(listResponse.List.Passwords))
	for _, objectName := range listResponse.List.Passwords {
		go func(objectName string) {
			getResponse, getError := handleGet(GetRequest{Name: objectName}, masterPW)
			if getError == nil {
				pw_chan <- PwResp{nil, objectName, getResponse.Get.Val}
			} else {
				pw_chan <- PwResp{getError, objectName, ""}
			}
		}(objectName)
	}

	// put all responses into a map
	passwords := make(map[string]string)
	for range listResponse.List.Passwords {
		pw_resp := <-pw_chan
		if pw_resp.err_ != nil {
			return Response{}, pw_resp.err_
		}
		passwords[pw_resp.objectName] = pw_resp.password
	}

	return Response{ExportPlain: &ExportPlainResponse{passwords}}, nil
}
