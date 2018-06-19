package keystore

import (
	"io/ioutil"
	"log"
	"strings"
	"time"
	"encoding/json"
	"github.com/cihub/seelog"
)

type FileOperator struct {
	Dir string
}

func (fo *FileOperator) Save(keystore KeyStore, account string) error {
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
		keystore := fo.ReadKeyStoreFromFile(fo.Dir + "/" + file.Name())
		if keystore.Address != "" {
			accounts = append(accounts, keystore.Address)
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
		if file.IsDir() {
			continue
		}
		keystore := fo.ReadKeyStoreFromFile(fo.Dir + "/" + file.Name())
		if keystore.Address == account {
			return keystore
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
