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
	merkleTree := NewMerkleTree("./ethash-data", 30000, false, 16)
	index := 100
	start := time.Now()
	proof, err := merkleTree.GetProofByRaw64ByteElementIndex(index)
	assert.Nil(t, err)
	values := [2][]byte{merkleTree.Raw64BytesDataElements[index], merkleTree.Raw64BytesDataElements[index+1]}
	indexes := [2]int{index, index + 1}
	merkleProof := NewMerkleProof(values, indexes, proof)
	assert.True(t, merkleProof.Validate(merkleTree.Hashes[0]))
	fmt.Println("proof took", time.Since(start))
	// todo remove merkle tree
}
