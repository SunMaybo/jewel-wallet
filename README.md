# jewel-wallet
## golang实现hd-wallet
###基于协议
     1. bips-32
     2. bips-39
     3. bips-44
### 支持
     1. 通过助记符生成钱包
     2. 通过keystore管理钱包
     3. 通过公钥匙衍生私钥和强衍生私钥
### 生成助记符

```golang
	m := Mnemonic{}
	//指定位数，选择语言
	fmt.Println(m.GenMnemonics(Seed256,dict.ENGLISH))
    
```
### 通过mnemonic，password，path获取Key
```golang
    mnemonic:="deny taste creek sudden dream indoor twenty check minor soft brand wolf category screen rude humor become knife focus moon insect pig egg shadow"

	keyChain := NewPathWithMnemonic("m/44'/0'/0'/0", mnemonic, "123456", Main, func(privateKey *ecdsa.PrivateKey) string {
		//获取以太币地址
		return crypto.PubkeyToAddress(privateKey.PublicKey).String()
	})
	
	fmt.Println(keyChain.Key().Address)

```

#### keystroe管理密钥
```golang
	m := Mnemonic{}
	keyChain := NewPathWithMnemonic("m/44'/0'/0'/0", m.GenMnemonics(Seed256, dict.ENGLISH), "", Main, func(privateKey *ecdsa.PrivateKey) string {
		//获取以太币地址
		return crypto.PubkeyToAddress(privateKey.PublicKey).String()
	})
	ks := keystore.KeyStore{}
	ks.AddressFunc = func(privateKey *ecdsa.PrivateKey) string {
		return crypto.PubkeyToAddress(privateKey.PublicKey).String()
	}
	ks.Dir = "./"
	address, error := ks.NewAccount(keyChain.Key(), "1234567", true)
	if error == nil {
		fmt.Println(address)
	}
	fmt.Println(ks.ListAccount())
 
```