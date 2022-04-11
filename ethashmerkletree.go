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
	hashWords          = 16      // Number of 32 bit ints in a hash
	datasetParents     = 256     // Number of parents of each dataset element
	cacheRounds        = 3       // Number of rounds in cache production
	loopAccesses       = 64      // Number of accesses in hashimoto loop
	algorithmRevision  = 23      // algorithmRevision is the data structure version used for file naming.
	pedersenHashBytes  = 32
	NULL_VALUE         = "0x"
	dataDir            = "./ethash-data"
	zokratesName       = "test"
	mtFileAppendix     = "_MERKLE_TREE"
)

type MerkleTree struct {
	ElementAmount          int
	Height                 int
	LeafAmount             int
	NodeAmount             int
	Raw64BytesDataElements [][]byte
	Hashes                 [][]byte
	logger                 zap.Logger
	FilePath               string
	isCache                bool
}

type MerkleProof struct {
	Proof   [][]byte
	Values  [2][]byte
	Indexes [2]int
	logger  zap.Logger
	// hasher function for validation function (if I try MiMC as well next to pedersen hash)
}

// MerkleProof currently only supports dataset item proofs
func NewMerkleProof(values [2][]byte, indexes [2]int, proof [][]byte) *MerkleProof {
	logger, _ := zap.NewProduction()
	return &MerkleProof{
		Values:  values,
		Indexes: indexes,
		Proof:   proof,
		logger:  *logger,
	}
}

func (mp *MerkleProof) Validate(root []byte) bool {
	pedersenHasher := pedersen.New(zokratesName, 171)
	sugar := mp.logger.Sugar()
	if mp.Indexes[0]+1 != mp.Indexes[1] {
		sugar.Error("Indexes are not consecutive.")
		return false
	}
	first64bytesPoint, _ := pedersenHasher.PedersenHashBytes(mp.Values[0])
	second64bytesPoint, _ := pedersenHasher.PedersenHashBytes(mp.Values[1])
	first64bytesHash := babyjub.Compress_Zokrates(first64bytesPoint)
	second64bytesHash := babyjub.Compress_Zokrates(second64bytesPoint)
	currPoint, err := pedersenHasher.PedersenHashBytes(append(first64bytesHash[:], second64bytesHash[:]...))
	if err != nil {
		sugar.Errorw(err.Error())
		return false
	}
	currHash := babyjub.Compress_Zokrates(currPoint)
	for i := 0; i < len(mp.Proof); i++ {
		currBit := mp.Indexes[0] >> i & 1
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

func NewMerkleTree(dirPath string, blockNr int, isCache bool, threads int, logger *zap.Logger) *MerkleTree {
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
	sugar.Debug(filePath)
	fileStats, err := os.Stat(filePath)
	if err != nil {
		sugar.Errorw(err.Error())
		return &MerkleTree{}
	}

	var elementAmount int
	// elementAmount := int(1024 % fileStats.Size())
	var height, leafAmount, nodeAmount int
	if isCache {
		elementAmount = int((fileStats.Size() - 8) / hashBytes)
	} else {
		elementAmount = int(((fileStats.Size() - 8) / hashBytes) / (mixBytes / hashBytes))
	}
	height = FindMtHeight(elementAmount)
	leafAmount = int(math.Pow(2, float64(height-1)))
	nodeAmount = int(math.Pow(2, float64(height)) - 1)

	// 3. creating elements array
	// allocating space for elements in a 2D slice
	elements := make([][]byte, int((fileStats.Size()-8)/hashBytes))
	var elementStorage []byte
	elementStorage = make([]byte, int((fileStats.Size() - 8)))

	// filling elements array
	fd, err := os.Open(filePath)
	if err != nil {
		sugar.Errorw(err.Error())
		return &MerkleTree{}
	}
	// jumping over magic number
	fd.Seek(8, 0)
	// read everything in one go into elementstorage
	currPointer := 0
	var read int
	for moreToRead := true; moreToRead; moreToRead = read > 0 {
		read, _ = fd.Read(elementStorage[currPointer:])
		currPointer += read
	}
	for i := range elements {
		elements[i], elementStorage = elementStorage[:hashBytes], elementStorage[hashBytes:]
	}

	// allocating space for hashes in a 2D slice
	// 4. init merkle tree
	mt := MerkleTree{
		ElementAmount:          elementAmount,
		LeafAmount:             leafAmount,
		NodeAmount:             nodeAmount,
		Height:                 height,
		Raw64BytesDataElements: elements,
		logger:                 *logger,
		FilePath:               mtFilePath,
		isCache:                isCache,
	}
	sugar.Infow("General Merkle Tree information", "elementAmount", elementAmount, "leafAmount", leafAmount, "nodeAmount", nodeAmount, "height", height, "isCache", isCache)
	// 5. create merkle tree
	mt.HashValuesInMT(threads)
	return &mt
}

func (mt *MerkleTree) HashValuesInMT(manualThreads int) {
	sugar := mt.logger.Sugar()
	start := time.Now()

	// create hash storage space
	hashes := make([][]byte, mt.NodeAmount)
	hashStorage := make([]byte, mt.NodeAmount*(pedersenHashBytes))
	// keeping this pointer in case of writing to file
	storagePointer := hashStorage
	fd, err := os.Open(mt.FilePath)
	if err == nil {
		currPointer := 0
		var read int
		for moreToRead := true; moreToRead; moreToRead = read > 0 {
			read, _ = fd.Read(hashStorage[currPointer:])
			currPointer += read
		}
		sugar.Infow("Read merkle tree from file", "filepath", mt.FilePath)
	}
	for i := range hashes {
		hashes[i], hashStorage = hashStorage[:pedersenHashBytes], hashStorage[pedersenHashBytes:]
	}
	mt.Hashes = hashes
	if err == nil {
		fd.Close()
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
			sugar.Debugw("Starting thread", "id", id)
			defer sugar.Debugw("Thread done.", "threadId", id)
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
			var hashIndex int
			// todo outsource loop into its own function
			sugar.Debugw("Starting walk through leafs", "thread_id", id, "first", first, "limit", limit)
			for i := first; i < limit; i++ {
				if !mt.isCache {
					// if not cache, i += 2 each iteration
					// dataset holds 128bytes elements in 64bytes chunks
					defer func() {
						i++
					}()

					hashIndex = i / 2
				} else {
					hashIndex = i
				}
				currHash = NULL_HASH
				if i < mt.LeafAmount+mt.ElementAmount-1 {
					// hardcoded zokratesName. If really used, change to seedhash maybe
					babyjubPoint, err := pedersenHasher.PedersenHashBytes(mt.Raw64BytesDataElements[i%(mt.LeafAmount-1)])
					if err != nil {
						sugar.Errorw(err.Error(), "threadId", id)
						return
					}
					if !mt.isCache {
						// hashing 128bytes of data together in one leaf since mixbytes is 128 and is used as such in calculating mixhash
						secondBabyjubPoint, err := pedersenHasher.PedersenHashBytes(mt.Raw64BytesDataElements[(i+1)%(mt.LeafAmount-1)])
						if err != nil {
							sugar.Errorw(err.Error(), "threadId", id)
							return
						}
						first64bytesHash := babyjub.Compress_Zokrates(babyjubPoint)
						second64bytesHash := babyjub.Compress_Zokrates(secondBabyjubPoint)
						concatenatedHash := append(first64bytesHash[:], second64bytesHash[:]...)
						babyjubPoint, err = pedersenHasher.PedersenHashBytes(concatenatedHash)
						if err != nil {
							sugar.Errorw(err.Error(), "threadId", id)
							return
						}
					}
					currHash = babyjub.Compress_Zokrates(babyjubPoint)
				}
				copy(mt.Hashes[hashIndex], currHash[:])

				if status := atomic.AddUint64(&progress, 1); status%percent == 0 {
					bar.Add(int(percent))
				}
			}
			sugar.Debugw("Leafs done.", "threadId", id, "start", first, "finish", limit)
			// inside of the tree
			var firstThreadNodeAtHeight, currNodeAmount, nodeAmountAtHeight int
			var leftHash []byte
			var rightHash []byte
			sugar.Debugw("Starting walk through inner nodes", "threadId", id)
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
			sugar.Debugw("Inner nodes done.", "threadId", id)
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
	currByteAmount := 0
	for moreToWrite := true; moreToWrite; moreToWrite = currByteAmount < len(storagePointer) {
		written, _ := fd.Write(storagePointer[currByteAmount:])
		currByteAmount += written
	}
}

// Get index of value in mt.raw64bytesdataelements
func (mt *MerkleTree) GetRaw64ByteElementIndex(value []byte) int {
	for i, element := range mt.Raw64BytesDataElements {
		if bytes.Equal(element, value) {
			return i
		} else if !mt.isCache && len(value) == mixBytes && bytes.Equal(element, value[:hashBytes]) && bytes.Equal(mt.Raw64BytesDataElements[i+1], value[hashBytes:]) {
			return i
		}
	}
	return -1
}

// Get index of value in merkle tree
func (mt *MerkleTree) GetHashIndex(value []byte) int {
	raw64bytesElementIndex := mt.GetRaw64ByteElementIndex(value)
	if raw64bytesElementIndex < 0 {
		// maybe we were given a hashValue
		for i, hashValue := range mt.Hashes[mt.LeafAmount-1:] {
			if bytes.Equal(hashValue, value) {
				return i
			}
		}
		return -1
	}
	if mt.isCache {
		return raw64bytesElementIndex + mt.LeafAmount - 1
	} else {
		// its a dataset: we have 128byte long leafs instead of 64
		return (raw64bytesElementIndex / 2) + mt.LeafAmount - 1
	}
}

// Get leaf hash value from element index in mt.Raw64BytesDataElements
func (mt *MerkleTree) GetHashValueByRawElementIndex(raw64ByteElementIndex int) ([]byte, error) {
	if (!mt.isCache && mt.NodeAmount <= int(raw64ByteElementIndex/2)+mt.LeafAmount-1) || (mt.isCache && mt.NodeAmount <= raw64ByteElementIndex+mt.LeafAmount-1) {
		return nil, errors.New("index not in Hashes slices.")
	}
	if mt.isCache {
		return mt.Hashes[raw64ByteElementIndex+mt.LeafAmount-1], nil
	} else {
		return mt.Hashes[int(raw64ByteElementIndex/2)+mt.LeafAmount-1], nil
	}
}

// Get node path by either hash value or actual value (64byte for cache and 128byte for dataset)
func (mt *MerkleTree) GetNodePathByValue(value []byte) []int {
	return mt.BuildNodePath(mt.GetHashIndex(value))
}

// Get node path by index in merkle tree
func (mt *MerkleTree) GetNodePathByIndex(index int) []int {
	return mt.BuildNodePath(index)
}

// Build node path by index in merkle tree
func (mt *MerkleTree) BuildNodePath(index int) []int {
	path := make([]int, mt.Height)

	currIndex := index
	for i := mt.Height - 1; i >= 0; i-- {
		path[i] = currIndex
		currIndex = int(currIndex/2) - (1 - (currIndex % 2))
	}
	return path
}

// Get value proof by raw 64 byte element index
func (mt *MerkleTree) GetProofByRaw64ByteElementIndex(raw64ByteElementIndex int) ([][]byte, error) {
	if mt.isCache {
		return mt.BuildProof(mt.GetNodePathByIndex(raw64ByteElementIndex + mt.LeafAmount - 1))
	} else {
		return mt.BuildProof(mt.GetNodePathByIndex(raw64ByteElementIndex/2 + mt.LeafAmount - 1))
	}
}

// Get value proof by either hash value or actual value (64byte for cache and 128byte for dataset)
func (mt *MerkleTree) GetProofByElementValue(value []byte) ([][]byte, error) {
	return mt.BuildProof(mt.GetNodePathByValue(value))
}

// Build proof by node path in merkle tree
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
	for smaller := true; smaller; smaller = int(math.Pow(2, currHeight)) <= elementAmount {
		currHeight++
	}
	// mt has (2 ** h) - 1 leafs and branches
	currHeight++
	return int(currHeight)
}
