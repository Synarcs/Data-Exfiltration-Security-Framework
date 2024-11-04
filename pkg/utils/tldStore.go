package utils

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"os"
	"path"
	"sync"
)

type ChunkRange struct {
	Start int64
	End   int64
}

type TopDomains struct {
	TopDomains *sync.Map
}

func getFileChunks(fileSize int64, workers int) []ChunkRange {
	var chunks []ChunkRange
	chunkSize := fileSize / int64(workers)
	var start int64 = 0

	for i := 0; i < workers-1; i++ {
		chunks = append(chunks, ChunkRange{Start: start, End: start + chunkSize})
		start += chunkSize
	}

	chunks = append(chunks, ChunkRange{Start: start, End: fileSize})
	return chunks
}

func processChunk(file *os.File, chunk ChunkRange, t *TopDomains, wg *sync.WaitGroup) {
	defer wg.Done()

	buffer := make([]byte, chunk.End-chunk.Start)
	_, err := file.ReadAt(buffer, chunk.Start)
	if err != nil {
		return
	}

	reader := bufio.NewReader(bytes.NewReader(buffer))
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}

		// contains a csv file and always with one column for parallel read
		fields := bytes.Split(line, []byte(","))
		domain := string(bytes.TrimSpace(fields[0]))
		t.TopDomains.Store(domain, true) // concurrent safe map for release lock consistency
	}
}

func VerifyTopDomainsData() (*TopDomains, error) {
	fd := path.Join("../data/top-host.csv")
	_, err := os.Stat(fd)

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Println("File does not exist")
		} else {
			log.Println("Runtime permission error please check the file stats and permission", err)
		}
		return nil, err
	}

	file, _ := os.Open(fd)
	fileInfo, _ := file.Stat()

	fileSize := fileInfo.Size()

	topDomains := &TopDomains{
		TopDomains: &sync.Map{},
	}
	defer file.Close()

	workers := GetCPUCores()
	chunkRanges := getFileChunks(fileSize, workers)

	var wg sync.WaitGroup
	for _, chunkRange := range chunkRanges {
		wg.Add(1)
		go processChunk(file, chunkRange, topDomains, &wg)
	}

	wg.Wait()

	if DEBUG {
		length := 0
		topDomains.TopDomains.Range(func(key, value interface{}) bool {
			length++
			return true
		})
		log.Println("Total domains found", length)
	}

	log.Println("File exists and Read via Parallel I/O for file stats", fileInfo.Name(), fileInfo.Size()/(1<<10)*3)

	return topDomains, nil
}
