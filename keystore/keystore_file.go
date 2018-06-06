package keystore

import (
	"io/ioutil"
	"log"
	"strings"
	"time"
	"encoding/json"
	"github.com/cihub/seelog"
	"os"
	"github.com/pkg/errors"
)

type FileOperator struct {
	Dir string
}

func (fo *FileOperator) Save(keystore KeyStore, account string, force bool) error {
	name := fo.existFile(account)
	if name != "" && !force {
		return errors.New("account keystore exist")
	}
	if name != "" {
		os.Remove(fo.Dir + "/" + name)
	}

	fileName := fo.Dir + "/" + "UTC--" + time.Now().Format("2006-01-02T15:04:05.999999999Z") + "--" + account + ".json"
	buff, err := json.Marshal(keystore)
	if err != nil {
		seelog.Error(err)
	}
	ioutil.WriteFile(fileName, buff, 0666)
	return nil

}
func (fo *FileOperator) ReadAccounts() (accounts []string) {
	dirList, e := ioutil.ReadDir(fo.Dir)
	if e != nil {
		log.Fatal(e)
	}
	for _, file := range dirList {
		if file.IsDir() {
			continue
		}
		if len(strings.Split(file.Name(), "--")) == 3 {
			accounts = append(accounts, strings.Split(strings.Split(file.Name(), "--")[2], ".")[0])
		}

	}
	return accounts
}
func (fo *FileOperator) ReadKeyStore(account string) KeyStore {
	dirList, e := ioutil.ReadDir(fo.Dir)
	if e != nil {
		log.Fatal(e)
	}
	for _, file := range dirList {
		if strings.Contains(file.Name(), account) {
			buff, err := ioutil.ReadFile(file.Name())
			if err != nil {
				log.Fatal(e)
			}
			ks := KeyStore{}
			json.Unmarshal(buff, &ks)
			return ks
		}
	}
	return KeyStore{}
}
func (fo *FileOperator) existFile(account string) string {
	dirList, e := ioutil.ReadDir(fo.Dir)
	if e != nil {
		log.Fatal(e)
	}
	for _, fileInfo := range dirList {
		if strings.Contains(fileInfo.Name(), account) {
			return fileInfo.Name()
		}
	}
	return ""
}
func (fo *FileOperator) ReadKeyStoreFromFile(fileName string) (KeyStore) {
	buff, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}
	ks := KeyStore{}
	json.Unmarshal(buff, &ks)
	return ks
}
