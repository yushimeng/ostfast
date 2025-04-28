package xunfeiasr

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type XunfeiOst struct {
	Host               string
	RequestUriCreate   string
	RequestUriQuery    string
	urlCreate          string
	urlQuery           string
	HttpMethod         string
	APPID              string
	Algorithm          string
	HttpProto          string
	UserName           string
	Secret             string
	Date               string
	BusinessArgsCreate map[string]interface{}
}

func (ost *XunfeiOst) updateDate() string {
	// # 设置当前时间
	// 'date': 'Wed, 29 Dec 2021 07:06:31 GMT'
	// Sun, 27 Apr 2025 02:00:17 UTC
	now := time.Now().UTC() // 获取当前的 UTC 时间
	// ost.Date = now.Format("Wed, 29 Dec 2021 07:06:31 GMT") // 格式化为 RFC 1123 格式的时间字符串
	ost.Date = now.Format(time.RFC1123) // 格式化为 RFC 1123 格式的时间字符串
	return ost.Date
}

func NewOSTFast(appid, apikey, apisecret string) *XunfeiOst {
	ost := &XunfeiOst{
		Host:             "ost-api.xfyun.cn",
		RequestUriCreate: "/v2/ost/pro_create",
		RequestUriQuery:  "/v2/ost/query",
	}
	// 	(1) host生成规则，例如：
	// https://upload-ost-api.xfyun.cn/file/upload 对应的Host为upload-ost-api.xfyun.cn
	// https://ost-api.xfyun.cn/v2/ost/query 对应的Host为ost-api.xfyun.cn

	// # 设置url
	// if re.match("^\d", ost.Host):
	// 如果ost.host 以数字开头，说明是IP地址
	// if 0 //ost.Host[0] >= '0' && ost.Host[0] <= '9' {
	// 	ost.urlCreate = "http://" + ost.Host + ost.RequestUriCreate
	// 	ost.urlQuery = "http://" + ost.Host + ost.RequestUriQuery
	// } else {
	// 	ost.urlCreate = "https://" + ost.Host + ost.RequestUriCreate
	// 	ost.urlQuery = "https://" + ost.Host + ost.RequestUriQuery
	// }
	ost.urlCreate = "https://" + ost.Host + ost.RequestUriCreate
	ost.urlQuery = "https://" + ost.Host + ost.RequestUriQuery

	ost.HttpMethod = "POST"
	ost.APPID = appid
	ost.Algorithm = "hmac-sha256"
	ost.HttpProto = "HTTP/1.1"
	ost.UserName = apikey
	ost.Secret = apisecret

	ost.updateDate()
	ost.BusinessArgsCreate = map[string]interface{}{
		"language": "zh_cn",
		"accent":   "mandarin",
		"domain":   "pro_ost_ed",
		"vspp_on":  1,    // # 是否开启说话人分离，默认为0 0：不开启 1：开启 注：目前mp3不支持角色分离
		"vto":      3000, //# vad强切控制，单位ms
	}
	return ost
}

func (ost *XunfeiOst) GetFileUrl(filepath string) (string, error) {
	api := NewSaveFile(ost.APPID, ost.UserName, ost.Secret, filepath)
	// 获取file size
	// 获取文件信息
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return "", err
	}
	// 获取文件大小，单位为字节
	file_size := fileInfo.Size()
	if file_size < 31457280 {
		fileurl, err := api.GeneParams("/upload")
		if err != nil {
			return "", err
		}

		return fileurl, nil
	}

	fileurl, err := api.GeneParams("/mpupload/upload")
	if err != nil {
		return "", err
	}

	return fileurl, nil
}

func (ost *XunfeiOst) get_create_body(fileurl string) string {
	post_data := map[string]interface{}{
		"common": map[string]interface{}{
			"app_id": ost.APPID,
		},
		"business": ost.BusinessArgsCreate,
		"data": map[string]interface{}{
			"audio_src": "http",
			"audio_url": fileurl,
			"encoding":  "raw",
		},
	}
	body, err := json.Marshal(post_data)
	if err != nil {
		return ""
	}
	return string(body)
}

func (ost *XunfeiOst) hashlib_256(res string) string {
	// 计算 SHA-256 哈希值
	hash := sha256.Sum256([]byte(res))
	// 将哈希值进行 Base64 编码
	base64Encoded := base64.StdEncoding.EncodeToString(hash[:])
	// 拼接结果字符串
	result := "SHA-256=" + base64Encoded
	return result
}

func (ost *XunfeiOst) generateSignature(digest, uri string) string {
	signature_str := "host: " + ost.Host + "\n"
	signature_str += "date: " + ost.Date + "\n"
	signature_str += ost.HttpMethod + " " + uri + " " + ost.HttpProto + "\n"
	signature_str += "digest: " + digest

	// 创建 HMAC-SHA256 哈希对象
	mac := hmac.New(sha256.New, []byte(ost.Secret))
	// 写入要签名的数据
	mac.Write([]byte(signature_str))
	// 计算签名
	signature := mac.Sum(nil)
	// 对签名进行 Base64 编码
	result := base64.StdEncoding.EncodeToString(signature)

	return result
}

func (ost *XunfeiOst) init_header(data, uri string) map[string]string {
	ost.Date = ost.updateDate()

	digest := ost.hashlib_256(data)
	sign := ost.generateSignature(digest, uri)
	// 构造 auth_header
	authHeader := fmt.Sprintf(`api_key="%s",algorithm="%s", headers="host date request-line digest", signature="%s"`,
		ost.UserName, ost.Algorithm, sign)

	// 构造请求头
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Accept":        "application/json",
		"Method":        "POST",
		"Host":          ost.Host,
		"Date":          ost.Date,
		"Digest":        digest,
		"Authorization": authHeader,
	}

	return headers
}

// 实现 get_query_body 功能的方法
func (ost *XunfeiOst) get_query_body(taskID string) (string, error) {
	// 构建请求数据
	postData := map[string]interface{}{
		"common": map[string]interface{}{
			"app_id": ost.APPID,
		},
		"business": map[string]interface{}{
			"task_id": taskID,
		},
	}

	// 将数据转换为 JSON 字节切片
	bodyBytes, err := json.Marshal(postData)
	if err != nil {
		return "", err
	}

	// 将字节切片转换为字符串
	return string(bodyBytes), nil
}

// Call 方法实现类似 Python 中 call 方法的功能
//
//	return json object
func (ost *XunfeiOst) call(url, body string, headers map[string]string) (interface{}, error) {
	// 创建一个带有超时的 HTTP 客户端
	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	// 将请求体转换为字节切片
	bodyBytes := []byte(body)

	// 创建 POST 请求
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		fmt.Printf("创建请求时出错: %v\n", err)
		return nil, err
	}

	// 设置请求头
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// 发送请求
	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("发送请求时出错: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 计算请求耗时
	interval := time.Since(startTime).Seconds()
	fmt.Printf("请求耗时: %f 秒\n", interval)

	// 读取响应内容
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应内容时出错: %v\n", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return respBody, nil
	}
	// {"code":0,"data":{"task_id":"250428101934461357198994"},"message":"success","sid":"ost000e1050@dx1967a3150bd6f22902"}
	// {"code":0,"data":{"force_refresh":"0","task_id":"250428102159794592588671","task_status":"2","task_type":"distribute_task"},"message":"success","sid":"ost000de066@dx1967a3388807c0e902"}
	fmt.Println("请求成功, responsebody:", string(respBody))
	var respData interface{}
	err = json.Unmarshal(respBody, &respData)
	if err != nil {
		fmt.Printf("解析 JSON 响应时出错: %v\n", err)
		return respBody, nil
	}

	return respData, nil
}

func (ost *XunfeiOst) task_create(fileurl string) (string, error) {
	body := ost.get_create_body(fileurl)
	headers_create := ost.init_header(body, ost.RequestUriCreate)
	task_id, err := ost.call(ost.urlCreate, body, headers_create)
	if err != nil {
		return "", err
	}
	task_id_str, ok := task_id.(map[string]interface{})["data"].(map[string]interface{})["task_id"].(string)
	if !ok {
		return "", fmt.Errorf("task_id is not string")
	}
	fmt.Println("task_id:", task_id_str)
	return task_id_str, nil
}

func (ost *XunfeiOst) task_query(task_id, fileurl string) (map[string]interface{}, error) {
	if len(task_id) > 0 {
		body := ost.get_create_body(fileurl)
		query_body, err := ost.get_query_body(task_id)
		if err != nil {
			return nil, err
		}
		headers_query := ost.init_header(body, ost.RequestUriQuery)
		result, err := ost.call(ost.urlQuery, query_body, headers_query)
		if err != nil {
			return nil, err
		}
		// 使用类型断言赋值给变量，避免在 case 分支中重复类型断言
		switch result := result.(type) {
		case map[string]interface{}:
			return result, nil
		case []uint8:
			return nil, fmt.Errorf("unexpect result:%s", string(result))
		}
		return result.(map[string]interface{}), nil
	}

	return nil, fmt.Errorf("task_id is empty")
}

func (ost *XunfeiOst) GetResult(fileurl string) (string, error) {
	fmt.Println("------ 创建任务 -------")
	task_id, err := ost.task_create(fileurl)
	if err != nil {
		return "", err
	}

	fmt.Println("------ 查询任务 -------")
	for {
		result, err := ost.task_query(task_id, fileurl)
		if err != nil {
			return "", err
		}

		if result["data"].(map[string]interface{})["task_status"].(string) != "1" &&
			result["data"].(map[string]interface{})["task_status"].(string) != "2" {
			data, err := json.Marshal(result)
			if err != nil {
				return "", err
			}
			return string(data), nil
		} else {
			fmt.Println("任务未完成，等待1秒后重试... task_status:", result["data"].(map[string]interface{})["task_status"].(string))
			time.Sleep(time.Second)
		}
	}
}
