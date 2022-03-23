package ethashmerkletree

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// func TestInitMerkleTree(t *testing.T) {
// 	// todo remove merkle tree
// 	merkleTree := NewMerkleTree("./ethash-data", 30000, false, 16)
// 	merkleTree.Elements = nil
// 	fmt.Println(hex.EncodeToString(merkleTree.Hashes[0]))
// 	merkleTree.Hashes = nil
// 	fmt.Println(merkleTree)
// }

func TestMerkleProofValidation(t *testing.T) {
	merkleTree := NewMerkleTree("./ethash-data", 30000, false, 0)
	index := 100
	start := time.Now()
	proof, err := merkleTree.GetProofByElementIndex(index)
	assert.Nil(t, err)
	merkleProof := NewMerkleProof(merkleTree.Elements[index], index, proof)
	assert.True(t, merkleProof.Validate(merkleTree.Hashes[0]))
	fmt.Println("proof took", time.Since(start))
	// todo remove merkle tree
}
