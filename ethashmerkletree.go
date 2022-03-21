package ethashmerkletree

import (
	"bytes"
	"encoding/hex"
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

type Merkletree struct {
	elementAmount int
	height        int
	leafAmount    int
	nodeAmount    int
	elements      [][]byte
	hashes        [][]byte
	logger        zap.Logger
	filePath      string
}

func New(dirPath string, blockNr int, isCache bool, threads int) *Merkletree {
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
		return &Merkletree{}
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
		return &Merkletree{}
	}
	// jumping over magic number
	fd.Seek(8, 0)
	for i := range elements {
		_, err := fd.Read(elements[i])
		if err != nil {
			sugar.Errorw(err.Error())
			return &Merkletree{}
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
	mt := Merkletree{
		elementAmount: elementAmount,
		leafAmount:    leafAmount,
		nodeAmount:    nodeAmount,
		height:        height,
		elements:      elements,
		hashes:        hashes,
		logger:        *logger,
		filePath:      mtFilePath,
	}
	// 6. create merkle tree
	mt.HashValuesInMT(threads)
	return &mt
}

func (mt *Merkletree) HashValuesInMT(manualThreads int) {
	sugar := mt.logger.Sugar()
	start := time.Now()
	// todo check if file is already there
	fd, err := os.Open(mt.filePath)
	if err == nil {
		for i := 0; i < mt.nodeAmount; i++ {
			fd.Read(mt.hashes[i])
		}
		sugar.Infow("Read merkle tree from file", "filepath", mt.filePath)
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
	bar := progressbar.Default(int64(mt.nodeAmount))
	// Calculate the dataset segment
	percent := uint64(math.Ceil(float64(mt.nodeAmount) / 100))
	for i := 0; i < int(threads); i++ {
		go func(id int) {
			defer sugar.Infow("thread done.", "threadId", id)
			defer pend.Done()
			pedersenHasher := pedersen.New(zokratesName, 171)
			var currHash [32]byte
			batch := mt.leafAmount / int(threads)

			// initial walk through the leafs
			first := mt.leafAmount + (id * batch) - 1
			limit := first + batch
			if limit > mt.nodeAmount {
				limit = mt.nodeAmount
			}
			// todo outsource loop into its own function
			for i := first; i < limit; i++ {
				if i < mt.leafAmount+mt.elementAmount-1 {
					// hardcoded zokratesName. If really used, change to seedhash maybe
					babyjubPoint, err := pedersenHasher.PedersenHashBytes(mt.elements[i%(mt.leafAmount-1)])
					if err != nil {
						sugar.Errorw(err.Error(), "threadId", id)
						return
					}
					currHash = babyjub.Compress_Zokrates(babyjubPoint)
					copy(mt.hashes[i], currHash[:])
				} else {
					// copy null hash without rehashing it.
					copy(mt.hashes[i], NULL_HASH[:])
				}
				if status := atomic.AddUint64(&progress, 1); status%percent == 0 {
					bar.Add(int(percent))
				}
			}
			// inside of the tree
			var firstThreadNodeAtHeight, currNodeAmount, nodeAmountAtHeight int
			var leftHash []byte
			var rightHash []byte
			for i := mt.height - 1; i > int(threadHeight); i-- {
				nodeAmountAtHeight = int(math.Pow(2, float64(i-1)))
				currNodeAmount = nodeAmountAtHeight / int(threads)
				firstThreadNodeAtHeight = nodeAmountAtHeight + (id * currNodeAmount) - 1
				limit = firstThreadNodeAtHeight + currNodeAmount
				if heightLimit := firstThreadNodeAtHeight + nodeAmountAtHeight; limit > heightLimit {
					limit = heightLimit
				}
				for j := firstThreadNodeAtHeight; j < limit; j++ {
					leftHash = mt.hashes[j*2+1]
					rightHash = mt.hashes[j*2+2]
					if bytes.Compare(leftHash, NULL_HASH[:]) != 0 || bytes.Compare(rightHash, NULL_HASH[:]) != 0 {
						babyjubPoint, err := pedersenHasher.PedersenHashBytes(leftHash, rightHash)
						if err != nil {
							sugar.Errorw(err.Error(), "threadId", id)
							return
						}
						currHash = babyjub.Compress_Zokrates(babyjubPoint)
						copy(mt.hashes[j], currHash[:])
					} else {
						// copy null hash without rehashing it.
						copy(mt.hashes[j], NULL_HASH[:])
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
			leftHash = mt.hashes[j*2+1]
			rightHash = mt.hashes[j*2+2]
			if bytes.Compare(leftHash, NULL_HASH[:]) != 0 || bytes.Compare(rightHash, NULL_HASH[:]) != 0 {
				babyjubPoint, err := pedersenHasher.PedersenHashBytes(leftHash, rightHash)
				if err != nil {
					sugar.Errorw(err.Error())
					return
				}
				currHash = babyjub.Compress_Zokrates(babyjubPoint)
				copy(mt.hashes[j], currHash[:])
			} else {
				// copy null hash without rehashing it.
				copy(mt.hashes[j], NULL_HASH[:])
			}
			if status := atomic.AddUint64(&progress, 1); status%percent == 0 {
				bar.Add(int(percent))
			}
		}
	}
	fd, err = os.OpenFile(mt.filePath, os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		sugar.Errorw(err.Error())
		panic(err.Error())
	}
	defer sugar.Infow("Wrote merkle tree to file", "filepath", mt.filePath)
	defer fd.Close()
	for i := 0; i < mt.nodeAmount; i++ {
		fd.Write(mt.hashes[i])
	}
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
