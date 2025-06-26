package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

var mvsocket string
var mvuri string

type mvServerResult struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

func MinivaultSetup(socket string) {
	mvsocket = socket
	mvuri = "http://minivault"
}

func MVDecrypt(data string) ([]byte, error) {
	mvclient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", mvsocket)
			},
		},
	}
	payload := `{"decrypt":{"data":"` + data + `"}}`
	response, err := mvclient.Post(mvuri+"/decrypt", "application/json", strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	var result mvServerResult
	d := json.NewDecoder(response.Body)
	d.DisallowUnknownFields()
	if err = d.Decode(&result); err != nil {
		return nil, err
	}
	if result.Status != "success" {
		return nil, errors.New(result.Msg)
	}
	return base64.URLEncoding.DecodeString(result.Msg)
}

func MVEncrypt(data []byte) (string, error) {
	mvclient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", mvsocket)
			},
		},
	}
	encodedData := base64.URLEncoding.EncodeToString(data)
	payload := `{"encrypt":{"data": "` + encodedData + `"}}`
	response, err := mvclient.Post(mvuri+"/encrypt", "application/json", strings.NewReader(payload))
	if err != nil {
		return "", err
	}
	var result mvServerResult
	d := json.NewDecoder(response.Body)
	d.DisallowUnknownFields()
	if err = d.Decode(&result); err != nil {
		return "", err
	}
	if result.Status != "success" {
		return "", errors.New(result.Msg)
	}
	return result.Msg, nil
}

func MVUnlock(username string, password string) error {
	mvclient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", mvsocket)
			},
		},
	}
	payload := `{"unlock": {"username":"` + username + `","password":"` + password + `"}}`
	response, err := mvclient.Post(mvuri+"/unlock", "application/json", strings.NewReader(payload))
	if err != nil {
		return err
	}
	var result mvServerResult
	d := json.NewDecoder(response.Body)
	d.DisallowUnknownFields()
	if err = d.Decode(&result); err != nil {
		return err
	}
	if result.Status != "success" {
		return errors.New(result.Msg)
	}
	return nil
}

func main() {
	MinivaultSetup("minivault.sock")
	// if minivault is not already unlocked, you can do:
	if err := MVUnlock("admin", "password"); err != nil {
		fmt.Println(err.Error())
		return
	}
	// encrypt a simple text string
	encryptedData, err := MVEncrypt([]byte("minivault test"))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("encrypted string: " + encryptedData)
	// decrypt the result on the way back out to your application
	decryptedData, err := MVDecrypt(encryptedData)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("decrypted string: " + string(decryptedData))
}
