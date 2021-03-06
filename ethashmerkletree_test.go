package ethashmerkletree

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
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
	logger, _ := zap.NewDevelopment()
	merkleTree := NewMerkleTree("./ethash-data", 30000, false, 0, logger)
	index := 60
	start := time.Now()
	proof, err := merkleTree.GetProofByRaw64ByteElementIndex(index)
	assert.Nil(t, err)
	values := [2][]byte{merkleTree.Raw64BytesDataElements[index], merkleTree.Raw64BytesDataElements[index+1]}
	indexes := [2]int{index, index + 1}
	merkleProof := NewMerkleProof(values, indexes, proof, logger)
	assert.True(t, merkleProof.Validate(merkleTree.Hashes[0]))
	fmt.Println("proof took", time.Since(start))
	// todo remove merkle tree
}
