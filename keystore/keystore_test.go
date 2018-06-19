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
}

func Test(t *testing.T) {
	fmt.Println(1 << 12)
}
