package wallet

import (
	"math/rand"
	"time"
	"encoding/binary"
	"bytes"
	"jewel-wallet/dict"
	"crypto/sha256"
	"encoding/hex"
)

var (
	Seed128 uint32 = 128
	Seed160 uint32 = 160
	Seed192 uint32 = 192
	Seed224 uint32 = 224
	Seed256 uint32 = 256
)

type Mnemonic []byte

func (m *Mnemonic) rand(bits uint32) (mnemonic Mnemonic) {
	var i uint32
	for i = 0; i < bits/64; i++ {
		bytesBuffer := bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, rand.NewSource(time.Now().UnixNano()).Int63())
		mnemonic = append(mnemonic, bytesBuffer.Bytes() ...)
	}
	return mnemonic
}
func (m *Mnemonic) RandMnemonic(bits uint32) Mnemonic {
	serial := m.rand(bits)
	return serial
}
func (m *Mnemonic) GenMnemonics(bits uint32, lang int8) string {
	return dict.Words(m.GenSerial(bits), lang)
}
func (m *Mnemonic) GenMnemonicsFromEntropy(entropy []byte, bits uint32, lang int8) string {
	return dict.Words(m.GenSerialFromEntropy(bits, entropy), lang)
}
func (m *Mnemonic) GenMnemonicsFromEntropyHex(entropyHex string, bits uint32, lang int8) string {
	bs, _ := hex.DecodeString(entropyHex)
	return dict.Words(m.GenSerialFromEntropy(bits, bs), lang)
}
func (m *Mnemonic) GenSerial(bits uint32) []uint16 {
	seeds, _ := m.RandomToSerial(m.rand(bits), bits)
	return seeds
}
func (m *Mnemonic) GenSerialFromEntropy(bits uint32, entropy []byte) []uint16 {
	serial, _ := m.RandomToSerial(entropy, bits)
	return serial
}
func (m *Mnemonic) RandomToSerial(seeds []byte, bits uint32) ([]uint16, uint32) {
	length := m.MnemonicWordLength(bits)
	return m.EncodeMnemonic(seeds, uint16(bits/32)), length
}
func (m *Mnemonic) EncodeMnemonic(datas []byte, suffix uint16) (seqs []uint16) {
	bitStr := m.ByteToBinaryString(datas)
	hash := sha256.New()
	hash.Write(datas)
	md := hash.Sum(nil)
	hashStr := m.ByteToBinaryString(md)
	bitStr += hashStr[0:suffix]
	for i := 0; i < len(bitStr); i ++ {
		if (i)%11 == 0 {
			end := i + 11
			if end >= len(bitStr) {
				end = len(bitStr)
			}
			seqs = append(seqs, m.BinaryStringTouint16(bitStr[i:end]))
		}
	}
	return seqs
}
func (m *Mnemonic) BinaryStringTouint16(s string) (val uint16) {

	var length uint16
	length = uint16(len(s))
	for i, item := range s {
		offset := length - uint16(i) - 1
		if item == 49 {
			val += 1 << offset
		}
	}
	return val
}

func (m *Mnemonic) ByteToBinaryString(datas []byte) (bitStr string) {
	var a byte
	for _, data := range datas {
		for i := 0; i < 8; i++ {
			a = data
			data <<= 1
			data >>= 1

			switch (a) {
			case data:
				bitStr += "0"
			default:
				bitStr += "1"
			}

			data <<= 1
		}
	}

	return bitStr
}

func (m *Mnemonic) MnemonicWordLength(bits uint32) uint32 {
	return (bits + bits/32) / 11
}
