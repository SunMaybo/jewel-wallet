package wallet

import (
	"testing"
	"crypto/ecdsa"
	"fmt"
	"github.com/SunMaybo/jewel-wallet/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/SunMaybo/jewel-wallet/dict"
)

func TestWallet(t *testing.T) {
	m := Mnemonic{}
	w := m.GenMnemonicsFromEntropyHex("00000000000000000000000000000000", Seed128, dict.ENGLISH)
	keyChain := NewPathWithMnemonic("m/44'/0'/0'/0", w, "", Main, func(privateKey *ecdsa.PrivateKey) string {
		return crypto.PubkeyToAddress(privateKey.PublicKey).String()
	})
	fmt.Println(keyChain.Key().Address)
	ks := keystore.KeyStore{}
	ks.AddressFunc = func(privateKey *ecdsa.PrivateKey) string {
		return crypto.PubkeyToAddress(privateKey.PublicKey).String()
	}
	ks.Dir = "./keystore"
	address, error := ks.NewAccount(keyChain.Key(), "1234567", true)
	if error == nil {
		fmt.Println(address)
	}
	fmt.Println(ks.ListAccount())
}
func TestMnemonic(t *testing.T) {
	m := Mnemonic{}
	fmt.Println(m.GenMnemonics(Seed256, dict.ENGLISH))
}
func TestKey(t *testing.T) {
	mnemonic := "deny taste creek sudden dream indoor twenty check minor soft brand wolf category screen rude humor become knife focus moon insect pig egg shadow"
	keyChain := NewPathWithMnemonic("m/44'/0'/0'/0", mnemonic, "123456", Main, func(privateKey *ecdsa.PrivateKey) string {
		//获取以太币地址
		return crypto.PubkeyToAddress(privateKey.PublicKey).String()
	})
	fmt.Println(keyChain.Key().Address)
}
func TestKeyStore(t *testing.T) {
	m := Mnemonic{}
	keyChain := NewPathWithMnemonic("m/44'/0'/0'/0", m.GenMnemonics(Seed256, dict.ENGLISH), "", Main, func(privateKey *ecdsa.PrivateKey) string {
		//获取以太币地址
		return crypto.PubkeyToAddress(privateKey.PublicKey).String()
	})
	ks := keystore.KeyStore{}
	ks.AddressFunc = func(privateKey *ecdsa.PrivateKey) string {
		return crypto.PubkeyToAddress(privateKey.PublicKey).String()
	}
	ks.Dir = "./keystore"
	address, error := ks.NewAccount(keyChain.Key(), "1234567", true)
	if error == nil {
		fmt.Println(address)
	}
	fmt.Println(ks.ListAccount())
}
