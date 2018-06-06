package wallet

import (
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha512"
	"golang.org/x/text/unicode/norm"
	"log"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"jewel-wallet/keystore"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/satori/go.uuid"
)

const SPLIT = 1 << 31

var (
	XPub, _ = hex.DecodeString("0488B21E")
	XPrv, _ = hex.DecodeString("0488ADE4")
	TPub, _ = hex.DecodeString("043587CF")
	TPrv, _ = hex.DecodeString("04358394")
)

func RootKey(mnemonic string, salt string) []byte {
	return pbkdf2.Key([]byte(norm.NFKD.String(mnemonic)), []byte(norm.NFKD.String("mnemonic"+salt)), 2048, 64, sha512.New)
}

type KeyChain struct {
	ChainCode        []byte
	MasterPrivateKey []byte
	MasterPublicKey  []byte
	Hardened         bool
	Deep             int
	Identifier       []byte
	FingerPrint      []byte
	NetWork          int
	Version          []byte
	I                []byte

	AddressFunc func(privateKey *ecdsa.PrivateKey) string
}

const (
	Main = iota
	Test
)

func NewMnemonic(bits uint32, lang int8) string {
	m := Mnemonic{}
	return m.GenMnemonics(bits, lang)
}

func NewPathWithMnemonic(path, mnemonic, password string, network int, addressFunc func(privateKey *ecdsa.PrivateKey) string) KeyChain {
	kc := New(mnemonic, password, network, addressFunc)
	driverPath, _ := ParseDerivationPath(path)
	for _, v := range driverPath {
		if v > 1<<31-1 {
			hV := v - 1<<31
			kc = kc.HardenedChild(int64(hV))
		} else {
			kc = kc.Child(int64(v))
		}
	}
	return kc
}

func New(mnemonic, password string, network int, addressFunc func(privateKey *ecdsa.PrivateKey) string) KeyChain {
	kc := KeyChain{}
	seeds := RootKey(mnemonic, password)
	fmt.Println(hex.EncodeToString(seeds))
	key := []byte("Bitcoin seed")
	mac := hmac.New(sha512.New, key)
	mac.Write(seeds)
	buff := mac.Sum(nil)
	//fmt.Println(hex.EncodeToString(buff))
	kc.ChainCode = buff[32:]
	kc.I = make([]byte, 4)
	kc.MasterPrivateKey = append(kc.MasterPrivateKey, make([]byte, 1)...)
	kc.MasterPrivateKey = append(kc.MasterPrivateKey, buff[0:32]...)
	kc.FingerPrint = make([]byte, 4)
	kc.NetWork = network
	kc.Hardened = false
	kc.AddressFunc = addressFunc
	return kc
}
func (kc *KeyChain) Child(index int64) KeyChain {

	hash := hmac.New(sha512.New, kc.ChainCode)
	var data []byte
	pub := privToPub(kc.MasterPrivateKey)
	data = append(data, pub...)
	data = append(data, uint32ToByte(uint32(index))...)
	hash.Write(data)
	hashCode := hash.Sum(nil)
	child := KeyChain{}
	child.MasterPrivateKey = addPrivKeys(hashCode[0:32], kc.MasterPrivateKey)
	child.ChainCode = hashCode[32:]
	child.Hardened = false
	child.Deep = kc.Deep + 1
	child.NetWork = kc.NetWork
	child.I = uint32ToByte(uint32(index))
	child.FingerPrint = hash160(privToPub(kc.MasterPrivateKey))[:4]
	child.AddressFunc = kc.AddressFunc
	return child
}
func (kc *KeyChain) HardenedChild(index int64) KeyChain {
	if index >= 1<<32 {
		log.Fatal("超出范围限制")
	}

	child := KeyChain{}
	hash := hmac.New(sha512.New, kc.ChainCode)
	var data []byte
	data = append(data, kc.MasterPrivateKey...)
	data = append(data, uint32ToByte(uint32(index+SPLIT)) ...)
	hash.Write(data)
	hashCode := hash.Sum(nil)
	child.MasterPrivateKey = addPrivKeys(hashCode[:32], kc.MasterPrivateKey)
	child.ChainCode = hashCode[32:]
	child.Hardened = true
	child.Deep = kc.Deep + 1
	child.NetWork = kc.NetWork
	child.I = uint32ToByte(uint32(index + SPLIT))
	child.FingerPrint = hash160(privToPub(kc.MasterPrivateKey))[:4]
	child.AddressFunc = kc.AddressFunc
	return child
}

func (kc *KeyChain) ChildPublic(index int64) KeyChain {

	hash := hmac.New(sha512.New, kc.ChainCode)
	var data []byte
	pub := privToPub(kc.MasterPrivateKey)
	data = append(data, pub...)
	data = append(data, uint32ToByte(uint32(index))...)
	hash.Write(data)
	hashCode := hash.Sum(nil)
	child := KeyChain{}
	child.MasterPrivateKey = addPubKeys(hashCode[0:32], privToPub(kc.MasterPrivateKey))
	child.ChainCode = hashCode[32:]
	child.Hardened = false
	child.Deep = kc.Deep + 1
	child.NetWork = kc.NetWork
	child.I = uint32ToByte(uint32(index))
	child.FingerPrint = hash160(kc.MasterPrivateKey)[:4]
	return child
}
func (kc *KeyChain) PublicKey() string {
	return hex.EncodeToString(privToPub(kc.MasterPrivateKey))
}

func (kc *KeyChain) Key() *keystore.Key {
	id, _ := uuid.NewV1()
	pk := crypto.ToECDSAUnsafe(kc.MasterPrivateKey[1:])
	return &keystore.Key{
		PrivateKey: pk,
		Id:         id,
		Address:    kc.AddressFunc(pk),
	}
}

func (kc *KeyChain) version(private bool) {
	if kc.NetWork == Main && private {
		kc.Version = XPrv
	}
	if kc.NetWork == Main && !private {
		kc.Version = XPub
	}
	if kc.NetWork == Test && private {
		kc.Version = TPrv
	}
	if kc.NetWork == Test && ! private {
		kc.Version = TPub
	}
}

type Serial []byte

func (kc *KeyChain) Serial(private bool) (Serial) {
	var buff Serial
	kc.version(private)
	buff = append(buff, kc.Version...)
	buff = append(buff, byte(kc.Deep))
	buff = append(buff, kc.FingerPrint...)
	buff = append(buff, kc.I ...)
	buff = append(buff, kc.ChainCode ...)
	if private {
		buff = append(buff, kc.MasterPrivateKey...)
	} else {
		buff = append(buff, privToPub(kc.MasterPrivateKey)...)
	}
	chkSum := dblSha256(buff)[:4]
	buff = append(buff, chkSum...)
	return buff
}

func (s Serial) EncodeString() string {
	return base58.Encode(s)
}
