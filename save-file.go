package xunfeiasr

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	lfasrHost            = "http://upload-ost-api.xfyun.cn/file"
	apiInit              = "/mpupload/init"
	apiUpload            = "/upload"
	apiCut               = "/mpupload/upload"
	apiCutComplete       = "/mpupload/complete"
	apiCutCancel         = "/mpupload/cancel"
	filePieceSize  int64 = 5242880 // 5M
)

type SeveFile struct {
	appID          string
	apiKey         string // username
	apiSecret      string
	requestID      string
	uploadFilePath string
	cloudID        string
}

func NewSaveFile(appID, apiKey, apiSecret, uploadFilePath string) *SeveFile {
	return &SeveFile{
		appID:          appID,
		apiKey:         apiKey,
		apiSecret:      apiSecret,
		requestID:      "0",
		uploadFilePath: uploadFilePath,
		cloudID:        "0",
	}
}

func (sf *SeveFile) getRequestID() string {
	return time.Now().Format("200601021504")
}

func (sf *SeveFile) hashlib256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	hashBytes := h.Sum(nil)
	return "SHA-256=" + base64.StdEncoding.EncodeToString(hashBytes)
}

func (sf *SeveFile) assembleAuthHeader(reqURL, fileDataType, method string, body string) map[string]string {
	u, _ := url.Parse(reqURL)
	host := u.Hostname()
	path := u.Path
	now := time.Now().UTC()
	date := now.Format(time.RFC1123)
	digest := sf.hashlib256("")
	signatureOrigin := fmt.Sprintf(
		"host: %s\ndate: %s\n%s %s HTTP/1.1\ndigest: %s",
		host, date, method, path, digest)

	mac := hmac.New(sha256.New, []byte(sf.apiSecret))
	mac.Write([]byte(signatureOrigin))
	signature := mac.Sum(nil)
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	authorization := fmt.Sprintf(`api_key="%s", algorithm="hmac-sha256", headers="host date request-line digest", signature="%s"`, sf.apiKey, signatureBase64)

	headers := map[string]string{
		"host":          host,
		"date":          date,
		"authorization": authorization,
		"digest":        digest,
		"content-type":  fileDataType,
	}
	return headers
}

func (sf *SeveFile) call(url, fileData, fileDataType string) (string, error) {
	headers := sf.assembleAuthHeader(url, fileDataType, "POST", fileData)
	// 设置http header
	req, err := http.NewRequest("POST", url, strings.NewReader(fileData))
	if err != nil {
		fmt.Printf("创建请求失败！Exception ：%v\n", err)
		return "", err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	//  设置body
	if fileData != "" {
		req.Header.Set("Content-Length", strconv.Itoa(len(fileData)))
	}

	// resp, err := http.Post(url, fileDataType, strings.NewReader(fileData))
	// 发送http post请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("该片上传失败！Exception ：%v\n", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应内容失败！Exception ：%v\n", err)
		return "", err
	}

	fmt.Printf("该片上传成功.状态：%d %s\n", resp.StatusCode, string(body))
	return string(body), nil
}

func (sf *SeveFile) uploadCutComplete(bodyDict map[string]interface{}) (string, error) {
	fileDataType := "application/json"
	url := lfasrHost + apiCutComplete
	body, err := json.Marshal(bodyDict)
	if err != nil {
		return "", err
	}

	respBody, err := sf.call(url, string(body), fileDataType)
	if err != nil {
		return "", err
	}
	var result map[string]interface{}
	err = json.Unmarshal([]byte(respBody), &result)
	if err != nil {
		return "", err
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("响应数据格式错误")
	}

	fileURL, ok := data["url"].(string)
	if !ok {
		return "", fmt.Errorf("无法获取文件 URL")
	}

	fmt.Println("任务上传结束")
	return fileURL, nil
}

// return url, error
func (sf *SeveFile) GeneParams(apiName string) (string, error) {
	sf.requestID = sf.getRequestID()
	bodyDict := make(map[string]interface{})

	switch apiName {
	case apiUpload:
		var buf bytes.Buffer
		// 打开文件
		file, err := os.Open(sf.uploadFilePath)
		if err != nil {
			fmt.Println("打开文件失败:", err)
			return "", err
		}
		defer file.Close()

		// 获取文件大小
		fileInfo, err := file.Stat()
		if err != nil {
			fmt.Println("获取文件信息失败:", err)
			return "", err
		}
		fmt.Printf("文件: %s 文件大小: %d 字节\n", sf.uploadFilePath, fileInfo.Size())
		writer := multipart.NewWriter(&buf)
		// 添加一个字段
		_ = writer.WriteField("app_id", sf.appID)
		_ = writer.WriteField("request_id", sf.getRequestID())

		/// 添加文件字段 (这里字段名是 "data")
		part, err := writer.CreateFormFile("data", filepath.Base(sf.uploadFilePath))
		if err != nil {
			fmt.Println("创建文件字段失败:", err)
			return "", err
		}
		_, err = io.Copy(part, file)
		if err != nil {
			fmt.Println("写入文件内容失败:", err)
			return "", err
		}

		// 必须关闭 writer，让最后的 boundary 正确写入
		writer.Close()

		url := lfasrHost + apiUpload
		// 设置 content-type 内容为 multipart/form-data，并包含正确的 boundary
		respBody, err := sf.call(url, buf.String(), writer.FormDataContentType())
		if err != nil {
			return "", err
		}
		respData := make(map[string]interface{})
		json.Unmarshal([]byte(respBody), &respData)

		// {"code":0,"sid":"fpt000179ee@dx19676a7ae349d0e802","data":{"url":"https://xfyun-seve-dx/IBAUEX+ollA5b/18xtFQFR+TYlU1dp7UqPcyprLi+OmSoTP5rs4yqpuE/W+SUe4FlDDCj/fkb2cy3v22yXPykzz80mZBzEacKRt8diLtQOn1ni78uEiPXbVmoYh6vtYHwnQ+syMF/S5hg8LMKQpjh8u4sJy29kuVUrjgi7FR8OcOrCPp+tEcOs9IuxHx7/fF9L43vIlBII0rYatd4/9u36zZdhwDl0V5O0ZGm+/JSI0YsAApKNGKZRle2Xz+A+4O+x+Q00HNrQAUm3ETJf2ouTJA5f0dFv2B7k1Rw+TDvIoBENuC+9rGx+/PVq1InY4VhskMlbON191OY7SF2mwophTQw0Ic3WCDugG3OdlmFc/MOFXBN9+4uSeUFKMfdBbX"},"message":"success"}
		uploadID, ok := respData["data"].(map[string]interface{})["url"].(string)
		if !ok {
			return "", fmt.Errorf("无法获取 url")
		}
		return uploadID, nil

	case apiInit:
		bodyDict["app_id"] = sf.appID
		bodyDict["request_id"] = sf.requestID
		bodyDict["cloud_id"] = sf.cloudID
		url := lfasrHost + apiInit
		respBody, err := sf.call(url, toJSON(bodyDict), "application/json")
		if err != nil {
			return "", err
		}
		var resultJson map[string]interface{}
		err = json.Unmarshal([]byte(respBody), &resultJson)
		if err != nil {
			return "", err
		}
		// {"code":0,"sid":"fpt0001c340@dx1967a4c2fc19d0f802","data":{"upload_id":"up_250428104855489325801309"},"message":"success"}
		return resultJson["data"].(map[string]interface{})["upload_id"].(string), nil
	case apiCut:
		uploadID, err := sf.prepareRequest()
		if err != nil {
			return "", err
		}

		err = sf.doUpload(sf.uploadFilePath, uploadID)
		if err != nil {
			return "", err
		}

		bodyDict["app_id"] = sf.appID
		bodyDict["request_id"] = sf.requestID
		bodyDict["upload_id"] = uploadID

		fileURL, err := sf.uploadCutComplete(bodyDict)
		if err != nil {
			return "", err
		}

		fmt.Printf("分片上传地址：%s\n", fileURL)
		return fileURL, nil
	default:
		return "", fmt.Errorf("不支持的 API 名称: %s", apiName)
	}
}

func (sf *SeveFile) prepareRequest() (string, error) {
	return sf.GeneParams(apiInit)
}

func (sf *SeveFile) doUpload(filePath, uploadID string) error {
	sliceId := 1
	// 打开文件
	file, err := os.Open(sf.uploadFilePath)
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return err
	}
	defer file.Close()
	// 获取文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("获取文件信息失败:", err)
		return err
	}
	fileTotalSize := fileInfo.Size()
	chunkSize := filePieceSize
	currentSize := chunkSize
	requestId := sf.getRequestID()
	chunks := int(math.Ceil(float64(fileTotalSize) / float64(chunkSize)))
	fmt.Printf("文件：%s 文件大小：%d 分块大小：%d 分块数：%d\n", filePath, fileTotalSize, chunkSize, chunks)
	for sliceId <= chunks {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		// 添加一个字段
		_ = writer.WriteField("app_id", sf.appID)
		_ = writer.WriteField("request_id", requestId)
		_ = writer.WriteField("upload_id", uploadID)
		_ = writer.WriteField("slice_id", strconv.Itoa(sliceId))
		if sliceId == chunks {
			currentSize = fileTotalSize - int64((chunks-1)*int(chunkSize))
		} else {
			currentSize = chunkSize
		}
		fmt.Printf("chunk %d, chunkSize %d\n", sliceId, currentSize)
		buffer := make([]byte, currentSize)
		_, err := file.Read(buffer)
		if err != nil {
			return err
		}
		part, err := writer.CreateFormFile("data", filepath.Base(sf.uploadFilePath))
		/// 添加文件字段 (这里字段名是 "data")
		if err != nil {
			fmt.Println("创建文件字段失败:", err)
			return err
		}
		_, err = io.Copy(part, bytes.NewBuffer(buffer))
		if err != nil {
			fmt.Println("写入文件内容失败:", err)
			return err
		}
		// 必须关闭 writer，让最后的 boundary 正确写入
		writer.Close()
		url := lfasrHost + apiCut
		for count := 0; count < 3; count++ {
			// 设置 content-type 内容为 multipart/form-data，并包含正确的 boundary
			respBody, err := sf.call(url, buf.String(), writer.FormDataContentType())
			if err == nil {
				fmt.Printf("该片上传成功.状态：%s\n", respBody)
				break
			}
			fmt.Printf("上传失败, 重试中...%d", count)
		}

		sliceId++
	}

	return nil
}

func toJSON(data interface{}) string {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(jsonData)
}
