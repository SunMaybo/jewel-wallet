package keystore

import (
	"github.com/satori/go.uuid"
	"crypto/ecdsa"
	crand "crypto/rand"
	"io"
	"encoding/hex"
	"crypto/aes"
	"math/big"
	"crypto/cipher"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/scrypt"
	"bytes"
	"fmt"
	"github.com/pkg/errors"
)

const (
	keyHeaderKDF = "scrypt"

	// StandardScryptN is the N parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptN = 1 << 18

	// StandardScryptP is the P parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptP = 1

	// LightScryptN is the N parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	LightScryptN = 1 << 12

	// LightScryptP is the P parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	LightScryptP = 6

	scryptR     = 8
	scryptDKLen = 32

	// number of bits in a big.Word
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes = wordBits / 8
)

type KeyStore struct {
	Crypto      Crypto                                              `json:"crypto"`
	ID          string                                              `json:"id"`
	Version     int                                                 `json:"version"`
	AddressFunc func(privateKey *ecdsa.PrivateKey) (address string) `json:"-"`
	Dir         string                                              `json:"-"`
}
type Crypto struct {
	Cipher       string       `json:"cipher"`
	CipherParams CipherParams `json:"cipherparams"`
	CipherText   string       `json:"ciphertext"`
	Kdf          string       `json:"kdf"`
	KdfParams    KdfParams    `json:"kdfparams"`
	Mac          string       `json:"mac"`
}
type CipherParams struct {
	Iv string `json:"iv"`
}
type KdfParams struct {
	Dklen int    `json:"dklen"`
	N     int    `json:"n"`
	P     int    `json:"p"`
	R     int    `json:"r"`
	Salt  string `json:"salt"`
}
type Key struct {
	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// to simplify lookups we also store the address
	Address string
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey *ecdsa.PrivateKey
}

func (k *KeyStore) Import(fileName string, auth string) error {
	fo := FileOperator{
		Dir: k.Dir,
	}
	keyStore := fo.ReadKeyStoreFromFile(fileName)
	key, err := k.DecryptKey(keyStore, auth)
	if err != nil {
		return err
	}
	keystore, err := k.EncryptKey(key, auth, LightScryptN, LightScryptP)
	if err != nil {
		return err
	}
	fo.Save(keystore, k.AddressFunc(key.PrivateKey), true)
	return nil
}

func (k *KeyStore) ListAccount() []string {
	fo := FileOperator{
		Dir: k.Dir,
	}
	return fo.ReadAccounts()
}
func (k *KeyStore) PrivateKey(account, auth string) (*Key, error) {
	fo := FileOperator{
		Dir: k.Dir,
	}
	keyStore := fo.ReadKeyStore(account)
	return k.DecryptKey(keyStore, auth)
}
func (k *KeyStore) NewAccount(key *Key, auth string, force bool) (string, error) {
	ks, err := k.EncryptKey(key, auth, LightScryptN, LightScryptP)
	if err != nil {
		return "", err
	}
	fo := FileOperator{
		Dir: k.Dir,
	}
	address := k.AddressFunc(key.PrivateKey)
	err = fo.Save(ks, address, force)
	if err != nil {
		return "", err
	}
	return address, nil
}
func (k *KeyStore) getEntropyCSPRNG(n int) []byte {
	mainBuff := make([]byte, n)
	_, err := io.ReadFull(crand.Reader, mainBuff)
	if err != nil {
		panic("reading from cr ypto/rand failed: " + err.Error())
	}
	return mainBuff
}

// EncryptKey encrypts a key using the specified scrypt parameters into a json
// blob that can be decrypted later on.
func (k *KeyStore) EncryptKey(key *Key, auth string, scryptN, scryptP int) (KeyStore, error) {
	authArray := []byte(auth)
	salt := k.getEntropyCSPRNG(32)
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return KeyStore{}, err
	}
	encryptKey := derivedKey[:16]
	keyBytes := PaddedBigBytes(key.PrivateKey.D, 32)

	iv := k.getEntropyCSPRNG(aes.BlockSize) // 16
	cipherText, err := aesCTRXOR(encryptKey, keyBytes, iv)
	if err != nil {
		return KeyStore{}, err
	}
	mac := crypto.Keccak256(derivedKey[16:32], cipherText)

	kdf := KdfParams{
		N:     scryptN,
		R:     scryptR,
		P:     scryptP,
		Dklen: scryptDKLen,
		Salt:  hex.EncodeToString(salt),
	}

	cipherParams := CipherParams{
		Iv: hex.EncodeToString(iv),
	}

	crypto := Crypto{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParams,
		Kdf:          keyHeaderKDF,
		KdfParams:    kdf,
		Mac:          hex.EncodeToString(mac),
	}

	keystore := KeyStore{
		Crypto:  crypto,
		ID:      key.Id.String(),
		Version: 3,
	}
	return keystore, nil
}
func (k *KeyStore) DecryptKey(m KeyStore, auth string) (*Key, error) {
	// Parse the json into a simple map to fetch the key version
	keyBytes, keyId, err := decryptKeyV3(m, auth)

	// Handle any decryption errors and return the key
	if err != nil {
		return nil, err
	}
	key := crypto.ToECDSAUnsafe(keyBytes)

	return &Key{
		Id:         uuid.FromStringOrNil(keyId),
		Address:    k.AddressFunc(key),
		PrivateKey: key,
	}, nil
}
func decryptKeyV3(keystore KeyStore, auth string) (keyBytes []byte, keyId string, err error) {

	if keystore.Crypto.Cipher != "aes-128-ctr" {
		return nil, "", fmt.Errorf("Cipher not supported: %v", keystore.Crypto.Cipher)
	}

	keyId = keystore.ID
	mac, err := hex.DecodeString(keystore.Crypto.Mac)
	if err != nil {
		return nil, "", err
	}

	iv, err := hex.DecodeString(keystore.Crypto.CipherParams.Iv)
	if err != nil {
		return nil, "", err
	}

	cipherText, err := hex.DecodeString(keystore.Crypto.CipherText)
	if err != nil {
		return nil, "", err
	}

	derivedKey, err := getKDFKey(keystore.Crypto, auth)
	if err != nil {
		return nil, "", err
	}

	calculatedMAC := crypto.Keccak256(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		return nil, "", errors.New("decode mac error")
	}

	plainText, err := aesCTRXOR(derivedKey[:16], cipherText, iv)
	if err != nil {
		return nil, "", err
	}
	return plainText, keyId, err
}
func getKDFKey(crypto Crypto, auth string) ([]byte, error) {
	authArray := []byte(auth)
	salt, err := hex.DecodeString(crypto.KdfParams.Salt)
	if err != nil {
		return nil, err
	}
	dkLen := ensureInt(crypto.KdfParams.Dklen)

	if crypto.Kdf == keyHeaderKDF {
		n := ensureInt(crypto.KdfParams.N)
		r := ensureInt(crypto.KdfParams.R)
		p := ensureInt(crypto.KdfParams.P)
		return scrypt.Key(authArray, salt, n, r, p, dkLen)

	}

	return nil, fmt.Errorf("Unsupported KDF: %s", crypto.Kdf)
}
func PaddedBigBytes(bigint *big.Int, n int) []byte {
	if bigint.BitLen()/8 >= n {
		return bigint.Bytes()
	}
	ret := make([]byte, n)
	ReadBits(bigint, ret)
	return ret
}
func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}
func ReadBits(bigint *big.Int, buf []byte) {
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}
func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}
