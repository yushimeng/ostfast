
package xunfeiASR

import (
  "fmt"  
)

func TestOST(t *testing.T) {
  filefullpath:= ""
  AppId :=""
  ApiKey:=""
  ApiSecret:=""
  
  ost := xunfeiasr.NewOSTFast(AppId, ApiKey, ApiSecret)
	fileurl, err := ost.GetFileUrl(filefullpath)
	if err != nil {
		t.Errorf("GetFileUrl")
	}
	result, err := ost.GetResult(fileurl)
	if err != nil {
		t.Errorf("GetResult")
	}
  fmt.Println(result)
}
