package keystore

import (
	"testing"
	"fmt"
	"time"
)

func TestFileOperator_Save(t *testing.T) {
	fo := FileOperator{
		Dir: "./",
	}
	fmt.Println(time.Now().Format("2006-01-02T15:04:05.999999999Z"))
	fmt.Println(fo.ReadAccounts())
	fo.Save(fo.ReadKeyStore("7ef5a6135f1fd6a02593eedc869c6d41d934aef8"),"7ef5a6135f1fd6a02593eedc869c6d41d934aef8")
}
