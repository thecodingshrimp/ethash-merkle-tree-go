package ethashmerkletree

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/stretchr/testify/assert"
)

func TestInitMerkleTree(t *testing.T) {
	// todo remove merkle tree
	merkleTree := NewMerkleTree("./ethash-data", 30000, true, 16)
	merkleTree.elements = nil
	fmt.Println(hex.EncodeToString(merkleTree.hashes[0]))
	merkleTree.hashes = nil
	fmt.Println(merkleTree)
}

func TestMerkleProofValidation(t *testing.T) {
	merkleTree := NewMerkleTree("./ethash-data", 30000, true, 16)
	index := 200000
	proof, err := merkleTree.GetProofByElementIndex(index)
	assert.Nil(t, err)
	merkleProof := NewMerkleProof(merkleTree.elements[index], index, proof)
	assert.True(t, merkleProof.validate(merkleTree.hashes[0]))
	// todo remove merkle tree
}

func TestComething(t *testing.T) {
	test := mimc7.MIMC7Hash(big.NewInt(0), big.NewInt(0))
	fmt.Println(test.Text(10))
	test = mimc7.MIMC7HashGeneric(big.NewInt(0), big.NewInt(0), 10)
	fmt.Println(test.Text(10))
}
