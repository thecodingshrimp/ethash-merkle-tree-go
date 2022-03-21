package ethashmerkletree

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestInitMerkleTree(t *testing.T) {
	test := New("./ethash-data", 30000, true, 16)
	test.elements = nil
	fmt.Println(hex.EncodeToString(test.hashes[0]))
	test.hashes = nil
	fmt.Println(test)
}
