package ethashmerkletree

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/schollz/progressbar/v3"
	"github.com/thecodingshrimp/pedersen-go"
	"github.com/thecodingshrimp/pedersen-go/babyjub"
	"go.uber.org/zap"
)

const (
	datasetInitBytes   = 1 << 30 // Bytes in dataset at genesis
	datasetGrowthBytes = 1 << 23 // Dataset growth per epoch
	cacheInitBytes     = 1 << 24 // Bytes in cache at genesis
	cacheGrowthBytes   = 1 << 17 // Cache growth per epoch
	epochLength        = 30000   // Blocks per epoch
	mixBytes           = 128     // Width of mix
	hashBytes          = 64      // Hash length in bytes
	pedersenHashBytes  = 32
	hashWords          = 16  // Number of 32 bit ints in a hash
	datasetParents     = 256 // Number of parents of each dataset element
	cacheRounds        = 3   // Number of rounds in cache production
	loopAccesses       = 64  // Number of accesses in hashimoto loop
	algorithmRevision  = 23  // algorithmRevision is the data structure version used for file naming.
	NULL_VALUE         = "0x"
	dataDir            = "./ethash-data"
	zokratesName       = "test"
	mtFileAppendix     = "_MERKLE_TREE"
)

type MerkleTree struct {
	ElementAmount int
	Height        int
	LeafAmount    int
	NodeAmount    int
	Elements      [][]byte
	Hashes        [][]byte
	logger        zap.Logger
	FilePath      string
}

type MerkleProof struct {
	Proof  [][]byte
	Value  []byte
	Index  int
	logger zap.Logger
	// hasher function for validation function (if I try MiMC as well next to pedersen hash)
}

func NewMerkleProof(value []byte, index int, proof [][]byte) *MerkleProof {
	logger, _ := zap.NewProduction()
	return &MerkleProof{
		Value:  value,
		Index:  index,
		Proof:  proof,
		logger: *logger,
	}
}

func (mp *MerkleProof) Validate(root []byte) bool {
	pedersenHasher := pedersen.New(zokratesName, 171)
	sugar := mp.logger.Sugar()
	currPoint, err := pedersenHasher.PedersenHashBytes(mp.Value)
	if err != nil {
		sugar.Errorw(err.Error())
		return false
	}
	currHash := babyjub.Compress_Zokrates(currPoint)
	for i := 0; i < len(mp.Proof); i++ {
		currBit := mp.Index >> i & 1
		switch currBit {
		case 1:
			currPoint, err = pedersenHasher.PedersenHashBytes(mp.Proof[len(mp.Proof)-i-1], currHash[:])
		default:
			currPoint, err = pedersenHasher.PedersenHashBytes(currHash[:], mp.Proof[len(mp.Proof)-i-1])
		}
		if err != nil {
			sugar.Errorw(err.Error())
			return false
		}
		currHash = babyjub.Compress_Zokrates(currPoint)
	}
	return bytes.Compare(root, currHash[:]) == 0
}

func NewMerkleTree(dirPath string, blockNr int, isCache bool, threads int) *MerkleTree {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sugar := logger.Sugar()
	// 1. generate data if its not there
	realDirPath := dataDir
	if dirPath != "" {
		realDirPath = dirPath
	}
	if isCache {
		ethash.MakeCache(uint64(blockNr), realDirPath)
	} else {
		ethash.MakeDataset(uint64(blockNr), realDirPath)
	}
	// 2. gather basic information about merkle tree
	fileName := FileNameCreator(isCache, blockNr)
	filePath := filepath.Join(dirPath, fileName)
	mtFilePath := fmt.Sprintf("%s%s", filePath, mtFileAppendix)
	sugar.Info(filePath)
	fileStats, err := os.Stat(filePath)
	if err != nil {
		sugar.Errorw(err.Error())
		return &MerkleTree{}
	}
	elementAmount := int((fileStats.Size() - 8)) / hashBytes
	// elementAmount := int(128 % fileStats.Size())
	height := FindMtHeight(elementAmount)
	leafAmount := int(math.Pow(2, float64(height-1)))
	nodeAmount := int(math.Pow(2, float64(height)) - 1)

	// 3. creating elements array
	// allocating space for elements in a 2D slice
	elements := make([][]byte, elementAmount)
	elementStorage := make([]byte, elementAmount*hashBytes)
	for i := range elements {
		elements[i], elementStorage = elementStorage[:hashBytes], elementStorage[hashBytes:]
	}
	// filling elements array
	fd, err := os.Open(filePath)
	if err != nil {
		sugar.Errorw(err.Error())
		return &MerkleTree{}
	}
	// jumping over magic number
	fd.Seek(8, 0)
	for i := range elements {
		_, err := fd.Read(elements[i])
		if err != nil {
			sugar.Errorw(err.Error())
			return &MerkleTree{}
		}
	}

	// 4. creating merkle tree array
	// allocating space for hashes in a 2D slice
	hashes := make([][]byte, nodeAmount)
	hashStorage := make([]byte, nodeAmount*(pedersenHashBytes))
	for i := range hashes {
		hashes[i], hashStorage = hashStorage[:pedersenHashBytes], hashStorage[pedersenHashBytes:]
	}
	// 5. init merkle tree
	mt := MerkleTree{
		ElementAmount: elementAmount,
		LeafAmount:    leafAmount,
		NodeAmount:    nodeAmount,
		Height:        height,
		Elements:      elements,
		Hashes:        hashes,
		logger:        *logger,
		FilePath:      mtFilePath,
	}
	// 6. create merkle tree
	mt.HashValuesInMT(threads)
	return &mt
}

func (mt *MerkleTree) HashValuesInMT(manualThreads int) {
	sugar := mt.logger.Sugar()
	start := time.Now()
	fd, err := os.Open(mt.FilePath)
	if err == nil {
		for i := 0; i < mt.NodeAmount; i++ {
			fd.Read(mt.Hashes[i])
		}
		sugar.Infow("Read merkle tree from file", "filepath", mt.FilePath)
		return
	}
	defer func() {
		elapsed := time.Since(start)

		logFn := sugar.Debugw
		if elapsed > 3*time.Second {
			logFn = sugar.Infow
		}
		logFn("Generated Ethash Merkle Tree", "elapsed", common.PrettyDuration(elapsed))
	}()
	// todo load from file if already generated

	// Generate the merkle tree on many goroutines since it takes a while
	possThreads := runtime.NumCPU()
	if manualThreads > 0 {
		possThreads = manualThreads
	}
	pedersenHasher := pedersen.New(zokratesName, 171)
	babyjubPoint, err := pedersenHasher.PedersenHashBytes([]byte(NULL_VALUE))
	if err != nil {
		sugar.Errorw(err.Error())
		return
	}
	NULL_HASH := babyjub.Compress_Zokrates(babyjubPoint)

	// need threads to be = 2 ^ n for any n
	threadHeight := math.Log2(float64(possThreads))
	if math.Trunc(threadHeight) != threadHeight {
		threadHeight = 0
		for math.Pow(2, float64(threadHeight)) <= float64(possThreads) {
			threadHeight++
		}
		threadHeight -= 1
	}
	threads := math.Pow(2, threadHeight)
	infoText := fmt.Sprintf("Using %d threads", int(threads))
	sugar.Info(infoText)

	var pend sync.WaitGroup
	pend.Add(int(threads))

	var progress uint64
	bar := progressbar.Default(int64(mt.NodeAmount))
	// Calculate the dataset segment
	percent := uint64(math.Ceil(float64(mt.NodeAmount) / 100))
	for i := 0; i < int(threads); i++ {
		go func(id int) {
			defer sugar.Infow("thread done.", "threadId", id)
			defer pend.Done()
			pedersenHasher := pedersen.New(zokratesName, 171)
			var currHash [32]byte
			batch := mt.LeafAmount / int(threads)

			// initial walk through the leafs
			first := mt.LeafAmount + (id * batch) - 1
			limit := first + batch
			if limit > mt.NodeAmount {
				limit = mt.NodeAmount
			}
			// todo outsource loop into its own function
			for i := first; i < limit; i++ {
				if i < mt.LeafAmount+mt.ElementAmount-1 {
					// hardcoded zokratesName. If really used, change to seedhash maybe
					babyjubPoint, err := pedersenHasher.PedersenHashBytes(mt.Elements[i%(mt.LeafAmount-1)])
					if err != nil {
						sugar.Errorw(err.Error(), "threadId", id)
						return
					}
					currHash = babyjub.Compress_Zokrates(babyjubPoint)
					copy(mt.Hashes[i], currHash[:])
				} else {
					// copy null hash without rehashing it.
					copy(mt.Hashes[i], NULL_HASH[:])
				}
				if status := atomic.AddUint64(&progress, 1); status%percent == 0 {
					bar.Add(int(percent))
				}
			}
			// inside of the tree
			var firstThreadNodeAtHeight, currNodeAmount, nodeAmountAtHeight int
			var leftHash []byte
			var rightHash []byte
			for i := mt.Height - 1; i > int(threadHeight); i-- {
				nodeAmountAtHeight = int(math.Pow(2, float64(i-1)))
				currNodeAmount = nodeAmountAtHeight / int(threads)
				firstThreadNodeAtHeight = nodeAmountAtHeight + (id * currNodeAmount) - 1
				limit = firstThreadNodeAtHeight + currNodeAmount
				if heightLimit := firstThreadNodeAtHeight + nodeAmountAtHeight; limit > heightLimit {
					limit = heightLimit
				}
				for j := firstThreadNodeAtHeight; j < limit; j++ {
					leftHash = mt.Hashes[j*2+1]
					rightHash = mt.Hashes[j*2+2]
					if bytes.Compare(leftHash, NULL_HASH[:]) != 0 || bytes.Compare(rightHash, NULL_HASH[:]) != 0 {
						babyjubPoint, err := pedersenHasher.PedersenHashBytes(leftHash, rightHash)
						if err != nil {
							sugar.Errorw(err.Error(), "threadId", id)
							return
						}
						currHash = babyjub.Compress_Zokrates(babyjubPoint)
						copy(mt.Hashes[j], currHash[:])
					} else {
						// copy null hash without rehashing it.
						copy(mt.Hashes[j], NULL_HASH[:])
					}
					if status := atomic.AddUint64(&progress, 1); status%percent == 0 {
						bar.Add(int(percent))
					}
				}
			}
		}(i)
	}
	// waiting for threads to finish
	pend.Wait()
	// hash the rest of the tree with main process.
	// todo outsource redundant code to its own function
	var currHash [32]byte
	var leftHash []byte
	var rightHash []byte
	for i := int(threadHeight); i > 0; i-- {
		nodeAmountAtHeight := int(math.Pow(2, float64(i-1)))
		currNodeAmount := nodeAmountAtHeight
		firstNodeAtHeight := nodeAmountAtHeight - 1
		limit := firstNodeAtHeight + currNodeAmount
		if heightLimit := nodeAmountAtHeight + nodeAmountAtHeight - 1; limit > heightLimit {
			limit = heightLimit
		}
		for j := firstNodeAtHeight; j < limit; j++ {
			leftHash = mt.Hashes[j*2+1]
			rightHash = mt.Hashes[j*2+2]
			if bytes.Compare(leftHash, NULL_HASH[:]) != 0 || bytes.Compare(rightHash, NULL_HASH[:]) != 0 {
				babyjubPoint, err := pedersenHasher.PedersenHashBytes(leftHash, rightHash)
				if err != nil {
					sugar.Errorw(err.Error())
					return
				}
				currHash = babyjub.Compress_Zokrates(babyjubPoint)
				copy(mt.Hashes[j], currHash[:])
			} else {
				// copy null hash without rehashing it.
				copy(mt.Hashes[j], NULL_HASH[:])
			}
			if status := atomic.AddUint64(&progress, 1); status%percent == 0 {
				bar.Add(int(percent))
			}
		}
	}
	fd, err = os.OpenFile(mt.FilePath, os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		sugar.Errorw(err.Error())
		panic(err.Error())
	}
	defer sugar.Infow("Wrote merkle tree to file", "filepath", mt.FilePath)
	defer fd.Close()
	for i := 0; i < mt.NodeAmount; i++ {
		fd.Write(mt.Hashes[i])
	}
}

func (mt *MerkleTree) GetElementIndex(value []byte) int {
	for i, element := range mt.Elements {
		if bytes.Equal(element, value) {
			return i
		}
	}
	return -1
}

func (mt *MerkleTree) GetHashIndex(value []byte) int {
	elementIndex := mt.GetElementIndex(value)
	if elementIndex < 0 {
		// maybe we were given a hashValue
		for i, hashValue := range mt.Hashes {
			if bytes.Equal(hashValue, value) {
				return i
			}
		}
		return -1
	}
	return elementIndex + mt.LeafAmount - 1
}

func (mt *MerkleTree) GetHashValueByElementIndex(index int) ([]byte, error) {
	if mt.NodeAmount <= index+mt.LeafAmount-1 {
		return nil, errors.New("index not in Hashes slices.")
	}
	return mt.Hashes[index+mt.LeafAmount-1], nil
}

func (mt *MerkleTree) GetNodePathByValue(value []byte) []int {
	return mt.BuildNodePath(mt.GetHashIndex(value))
}

func (mt *MerkleTree) GetNodePathByIndex(index int) []int {
	return mt.BuildNodePath(index)
}

func (mt *MerkleTree) BuildNodePath(index int) []int {
	path := make([]int, mt.Height)
	currIndex := index
	for i := mt.Height - 1; i >= 0; i-- {
		path[i] = currIndex
		currIndex = int(currIndex/2) - (1 - (currIndex % 2))
	}
	return path
}

func (mt *MerkleTree) GetProofByElementIndex(index int) ([][]byte, error) {
	return mt.BuildProof(mt.GetNodePathByIndex(index + mt.LeafAmount - 1))
}

func (mt *MerkleTree) GetProofByElementValue(value []byte) ([][]byte, error) {
	return mt.BuildProof(mt.GetNodePathByValue(value))
}

func (mt *MerkleTree) BuildProof(nodePath []int) ([][]byte, error) {
	proof := make([][]byte, mt.Height-1)
	proofStorage := make([]byte, (mt.Height-1)*pedersenHashBytes)
	for i := range proof {
		proof[i], proofStorage = proofStorage[:pedersenHashBytes], proofStorage[pedersenHashBytes:]
	}

	for i := len(nodePath) - 1; i > 0; i-- {
		switch nodePath[i] % 2 {
		case 0:
			proof[i-1] = mt.Hashes[nodePath[i]-1]
		default:
			proof[i-1] = mt.Hashes[nodePath[i]+1]
		}
	}
	return proof, nil
}

func FileNameCreator(isCache bool, blockNr int) string {
	first8ByteSeedHash := hex.EncodeToString(ethash.SeedHash(uint64(blockNr))[:8])
	if isCache {
		return fmt.Sprintf("cache-R%v-%v", algorithmRevision, first8ByteSeedHash)
	}
	return fmt.Sprintf("full-R%v-%v", algorithmRevision, first8ByteSeedHash)
}

func FindMtHeight(elementAmount int) int {
	currHeight := float64(1)
	// mt has 2 ** (h - 1) leafs.
	for smaller := true; smaller; smaller = int(math.Pow(2, currHeight)) < elementAmount {
		currHeight++
	}
	// mt has (2 ** h) - 1 leafs and branches
	currHeight++
	return int(currHeight)
}
