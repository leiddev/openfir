// Copyright 2026 The OpenFIR Authors.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// OpenFIR Protocol Constants & Frame Definitions
// OpenFIR = Open Fast Interleaved Reliable UDP Transport Protocol
// ============================================================================

const (
	ProtocolMagic0 = 0x4F // 'O'
	ProtocolMagic1 = 0x46 // 'F'

	PktHandshake    uint8 = 0x01 // Session metadata synchronization
	PktHandshakeAck uint8 = 0x02 // Idempotent handshake acknowledgment
	PktData         uint8 = 0x03 // Standard data payload frame
	PktTeleport     uint8 = 0x04 // In-flight content-addressed zero-byte teleport frame
	PktPhiParity    uint8 = 0x05 // Coprime-stride interleaved GF(2) parity frame
	PktFeedback     uint8 = 0x06 // Receiver NACK bitmap + Kalman OWDG feedback frame
	PktFin          uint8 = 0x07 // Transfer completion announcement
	PktFinAck       uint8 = 0x08 // End-to-end SHA-256 verification confirmation

	FlagSingleFile      uint8 = 0x00 // Payload represents a single regular file
	FlagDirectoryBundle uint8 = 0x01 // Payload represents a Virtual Continuous Directory Extent

	DefaultChunkSize  = 1200             // Safe UDP payload size across WANs and tunnels
	MaxUDPPacketSize  = 1500             // Maximum UDP datagram buffer size
	SocketBufferBytes = 16 * 1024 * 1024 // 16 MB kernel socket buffer target
	PhiWindowSize     = 20               // Sliding window size for coprime interleaving
	PhiStride         = 5                // Coprime stride (5 * 4 = 20); absorbs 5-packet burst losses
	PhiGroupMembers   = 4                // Data chunks per algebraic parity equation
	MaxPendingParity  = 512              // Maximum active equations in peeling decoder graph
	MaxNackPerPacket  = 180              // Maximum NACK chunk IDs per feedback frame
	MaxTrackedPeers   = 16               // Maximum concurrent client UDP paths tracked per session
	L1ChunkCacheSize  = 512              // Receiver in-memory L1 ring cache slots for zero-disk-read healing
)

var (
	wireHeaderPrefix = [6]byte{'O', 'F', 'I', 'R', 'v', '1'}
	entryMagicBytes  = [4]byte{'O', 'F', 'E', 'N'}
	packetBufferPool = sync.Pool{
		New: func() any {
			b := make([]byte, MaxUDPPacketSize+256)
			return &b
		},
	}
)

// ============================================================================
// Module 1: OFIRv1 Cleartext-Header-Authenticated AES-256-GCM Wire Security
// ============================================================================

var (
	aeadMu            sync.RWMutex
	cachedAEAD        cipher.AEAD
	cachedSecret      uint64
	cachedInitialized bool
)

func splitMix64Next(state *uint64) uint64 {
	*state += 0x9e3779b97f4a7c15
	z := *state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func cryptoRandUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(b[:])
}

func getAEAD(secret uint64) cipher.AEAD {
	aeadMu.RLock()
	if cachedInitialized && cachedSecret == secret {
		a := cachedAEAD
		aeadMu.RUnlock()
		return a
	}
	aeadMu.RUnlock()

	aeadMu.Lock()
	defer aeadMu.Unlock()
	if cachedInitialized && cachedSecret == secret {
		return cachedAEAD
	}

	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], secret)
	key256 := sha256.Sum256(seed[:])
	block, err := aes.NewCipher(key256[:])
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	cachedSecret = secret
	cachedAEAD = aead
	cachedInitialized = true
	return aead
}

// cloakPacket encapsulates an inner frame into an authenticated wire datagram:
// [6B Printable ASCII "OFIRv1" (AAD)][12B Whitened Nonce][AES-256-GCM Ciphertext + 16B Tag]
func cloakPacket(raw []byte, secret uint64, seq uint64) []byte {
	aead := getAEAD(secret)
	nonceSize := aead.NonceSize() // 12 bytes

	state := secret ^ seq
	n0 := splitMix64Next(&state)
	n1 := splitMix64Next(&state)

	out := make([]byte, 6+nonceSize, 6+nonceSize+len(raw)+aead.Overhead())
	copy(out[0:6], wireHeaderPrefix[:])
	binary.BigEndian.PutUint64(out[6:14], n0)
	binary.BigEndian.PutUint32(out[14:18], uint32(n1))

	out = aead.Seal(out, out[6:6+nonceSize], raw, out[0:6])
	return out
}

// uncloakPacket verifies the "OFIRv1" header and authenticates/decrypts the AES-256-GCM payload.
func uncloakPacket(wire []byte, secret uint64) ([]byte, bool) {
	aead := getAEAD(secret)
	nonceSize := aead.NonceSize()
	if len(wire) < 6+nonceSize+aead.Overhead()+3 {
		return nil, false
	}
	for i := 0; i < 6; i++ {
		if wire[i] != wireHeaderPrefix[i] {
			return nil, false
		}
	}

	aad := wire[0:6]
	nonce := wire[6 : 6+nonceSize]
	ciphertext := wire[6+nonceSize:]

	raw, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, false
	}
	if len(raw) < 3 || raw[0] != ProtocolMagic0 || raw[1] != ProtocolMagic1 {
		return nil, false
	}
	return raw, true
}

// ============================================================================
// Module 2: Zero-RTT Virtual Continuous Extent (Massive Small-Files Engine)
// Maps an entire directory tree onto a single deterministic virtual byte stream
// in memory with O(log N) random-access ReadAt and zero temporary disk usage.
// Entry Format: [4B "OFEN"][4B Mode][8B FileSize][2B PathLen][SlashPath][Data...]
// ============================================================================

type virtualEntry struct {
	absPath     string
	headerBytes []byte
	fileSize    int64
	startOffset int64
	endOffset   int64
}

type VirtualDirectoryExtent struct {
	entries   []virtualEntry
	totalSize int64

	mu         sync.Mutex
	cachedPath string
	cachedFile *os.File
}

func NewVirtualDirectoryExtent(rootDir string) (*VirtualDirectoryExtent, error) {
	rootDir = filepath.Clean(rootDir)
	var entries []virtualEntry
	var currentOffset int64 = 0

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		rel, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}
		slashRel := filepath.ToSlash(rel)
		relBytes := []byte(slashRel)
		if len(relBytes) == 0 || len(relBytes) > 65535 {
			return nil
		}

		fSize := info.Size()
		hdr := make([]byte, 18+len(relBytes))
		copy(hdr[0:4], entryMagicBytes[:])
		binary.BigEndian.PutUint32(hdr[4:8], uint32(info.Mode().Perm()))
		binary.BigEndian.PutUint64(hdr[8:16], uint64(fSize))
		binary.BigEndian.PutUint16(hdr[16:18], uint16(len(relBytes)))
		copy(hdr[18:], relBytes)

		entrySpan := int64(len(hdr)) + fSize
		entries = append(entries, virtualEntry{
			absPath:     path,
			headerBytes: hdr,
			fileSize:    fSize,
			startOffset: currentOffset,
			endOffset:   currentOffset + entrySpan,
		})
		currentOffset += entrySpan
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &VirtualDirectoryExtent{
		entries:   entries,
		totalSize: currentOffset,
	}, nil
}

func (v *VirtualDirectoryExtent) Size() int64 {
	return v.totalSize
}

func (v *VirtualDirectoryExtent) FileCount() int {
	return len(v.entries)
}

func (v *VirtualDirectoryExtent) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cachedFile != nil {
		err := v.cachedFile.Close()
		v.cachedFile = nil
		v.cachedPath = ""
		return err
	}
	return nil
}

func (v *VirtualDirectoryExtent) readEntryFileAt(absPath string, dst []byte, fileOffset int64) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.cachedPath != absPath || v.cachedFile == nil {
		if v.cachedFile != nil {
			_ = v.cachedFile.Close()
			v.cachedFile = nil
			v.cachedPath = ""
		}
		f, err := os.Open(absPath)
		if err != nil {
			return 0, err
		}
		v.cachedFile = f
		v.cachedPath = absPath
	}
	return v.cachedFile.ReadAt(dst, fileOffset)
}

// ReadAt satisfies io.ReaderAt across the virtual continuous directory extent in O(log N).
func (v *VirtualDirectoryExtent) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= v.totalSize {
		return 0, io.EOF
	}
	idx := sort.Search(len(v.entries), func(i int) bool {
		return v.entries[i].endOffset > off
	})

	totalCopied := 0
	curOff := off

	for totalCopied < len(p) && idx < len(v.entries) {
		e := &v.entries[idx]
		relOff := curOff - e.startOffset
		hdrLen := int64(len(e.headerBytes))

		if relOff < hdrLen {
			availHdr := int(hdrLen - relOff)
			need := len(p) - totalCopied
			if availHdr > need {
				availHdr = need
			}
			copy(p[totalCopied:totalCopied+availHdr], e.headerBytes[relOff:int(relOff)+availHdr])
			totalCopied += availHdr
			curOff += int64(availHdr)
			relOff += int64(availHdr)
		}

		if totalCopied < len(p) && relOff >= hdrLen {
			fileOff := relOff - hdrLen
			availFile := e.fileSize - fileOff
			if availFile > 0 {
				need := int64(len(p) - totalCopied)
				toRead := availFile
				if toRead > need {
					toRead = need
				}
				n, err := v.readEntryFileAt(e.absPath, p[totalCopied:totalCopied+int(toRead)], fileOff)
				totalCopied += n
				curOff += int64(n)
				if err != nil && err != io.EOF {
					return totalCopied, err
				}
			}
		}
		idx++
	}

	if totalCopied < len(p) {
		return totalCopied, io.EOF
	}
	return totalCopied, nil
}

// unpackDirectoryBundle extracts a verified virtual continuous extent staging file into targetRootDir.
func unpackDirectoryBundle(bundleFile *os.File, bundleSize int64, targetRootDir string) (int, error) {
	if err := os.MkdirAll(targetRootDir, 0755); err != nil {
		return 0, err
	}
	var offset int64 = 0
	var extractedCount int = 0
	hdrBuf := make([]byte, 18)
	copyBuf := make([]byte, 256*1024)

	for offset < bundleSize {
		if offset+18 > bundleSize {
			return extractedCount, errors.New("corrupted directory bundle entry header")
		}
		if _, err := bundleFile.ReadAt(hdrBuf, offset); err != nil && err != io.EOF {
			return extractedCount, err
		}
		for i := 0; i < 4; i++ {
			if hdrBuf[i] != entryMagicBytes[i] {
				return extractedCount, errors.New("invalid entry magic in directory bundle")
			}
		}
		filePerm := fs.FileMode(binary.BigEndian.Uint32(hdrBuf[4:8])) & 0777
		if filePerm == 0 {
			filePerm = 0644
		}
		fileSize := int64(binary.BigEndian.Uint64(hdrBuf[8:16]))
		pathLen := int(binary.BigEndian.Uint16(hdrBuf[16:18]))
		offset += 18

		if pathLen <= 0 || offset+int64(pathLen)+fileSize > bundleSize {
			return extractedCount, errors.New("corrupted entry bounds in directory bundle")
		}
		pathBytes := make([]byte, pathLen)
		if _, err := bundleFile.ReadAt(pathBytes, offset); err != nil && err != io.EOF {
			return extractedCount, err
		}
		offset += int64(pathLen)

		// Sanitize relative path to prevent path traversal (Zip-Slip protection)
		cleanRel := filepath.Clean(filepath.FromSlash(string(pathBytes)))
		if strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
			return extractedCount, errors.New("unsafe relative path rejected during bundle extraction")
		}

		dstPath := filepath.Join(targetRootDir, cleanRel)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return extractedCount, err
		}

		outF, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
		if err != nil {
			return extractedCount, err
		}

		rem := fileSize
		for rem > 0 {
			step := int64(len(copyBuf))
			if rem < step {
				step = rem
			}
			n, rErr := bundleFile.ReadAt(copyBuf[:step], offset)
			if n > 0 {
				if _, wErr := outF.Write(copyBuf[:n]); wErr != nil {
					_ = outF.Close()
					return extractedCount, wErr
				}
				offset += int64(n)
				rem -= int64(n)
			}
			if rErr != nil && rErr != io.EOF {
				_ = outF.Close()
				return extractedCount, rErr
			}
		}
		_ = outF.Close()
		extractedCount++
	}
	return extractedCount, nil
}

// ============================================================================
// Module 3: Kalman-Filtered One-Way Delay Gradient (KF-OWDG) Tracker
// ============================================================================

type KalmanOWDTracker struct {
	mu              sync.Mutex
	initialized     bool
	lastSendNano    int64
	lastRecvNano    int64
	minOneWayOffset int64
	hatGradMicros   float64
	errCovP         float64
	processNoiseQ   float64
	measureNoiseR   float64
	standingQueueUs int64
}

func NewKalmanOWDTracker() *KalmanOWDTracker {
	return &KalmanOWDTracker{
		minOneWayOffset: math.MaxInt64,
		errCovP:         100.0,
		processNoiseQ:   8.0,
		measureNoiseR:   220.0,
	}
}

func (k *KalmanOWDTracker) Observe(sendNano, recvNano int64) {
	if sendNano <= 0 || recvNano <= 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	oneWay := recvNano - sendNano
	if oneWay < k.minOneWayOffset {
		k.minOneWayOffset = oneWay
	} else {
		k.minOneWayOffset += (oneWay - k.minOneWayOffset) / 100000
	}
	k.standingQueueUs = (oneWay - k.minOneWayOffset) / 1000

	if !k.initialized {
		k.initialized = true
		k.lastSendNano = sendNano
		k.lastRecvNano = recvNano
		return
	}

	if sendNano > k.lastSendNano {
		deltaSend := sendNano - k.lastSendNano
		deltaRecv := recvNano - k.lastRecvNano
		measuredGradUs := float64(deltaRecv-deltaSend) / 1000.0

		if measuredGradUs > -50000 && measuredGradUs < 50000 {
			pPred := k.errCovP + k.processNoiseQ
			kalmanGain := pPred / (pPred + k.measureNoiseR)
			k.hatGradMicros = k.hatGradMicros + kalmanGain*(measuredGradUs-k.hatGradMicros)
			k.errCovP = (1.0 - kalmanGain) * pPred
		}
		k.lastSendNano = sendNano
		k.lastRecvNano = recvNano
	}
}

func (k *KalmanOWDTracker) Snapshot() (gradMicros int64, queueMicros int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return int64(k.hatGradMicros), k.standingQueueUs
}

// ============================================================================
// Module 4: Micro-Burst Token-Bucket Rate Pacer
// ============================================================================

type MicroPacer struct {
	mu           sync.Mutex
	rateBps      float64
	minRateBps   float64
	maxRateBps   float64
	tokens       float64
	lastRefill   time.Time
	maxBurstSize float64
}

func NewMicroPacer(initialMBps, minMBps, maxMBps float64) *MicroPacer {
	initBps := initialMBps * 1024 * 1024
	return &MicroPacer{
		rateBps:      initBps,
		minRateBps:   minMBps * 1024 * 1024,
		maxRateBps:   maxMBps * 1024 * 1024,
		tokens:       64 * 1024,
		lastRefill:   time.Now(),
		maxBurstSize: 64 * 1024,
	}
}

func (p *MicroPacer) Wait(bytesToSend int) {
	p.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(p.lastRefill).Seconds()
	p.lastRefill = now

	p.tokens += elapsed * p.rateBps
	if p.tokens > p.maxBurstSize {
		p.tokens = p.maxBurstSize
	}
	p.tokens -= float64(bytesToSend)

	var sleepDur time.Duration
	if p.tokens < 0 {
		waitSec := (-p.tokens) / p.rateBps
		sleepDur = time.Duration(waitSec * float64(time.Second))
	}
	p.mu.Unlock()

	if sleepDur > 400*time.Microsecond {
		time.Sleep(sleepDur)
	}
}

func (p *MicroPacer) UpdateFromKalman(gradMicros, standingQueueUs int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	const targetQueueUs = 4000

	if gradMicros < 40 && standingQueueUs < targetQueueUs {
		p.rateBps = p.rateBps*1.06 + 512*1024
	} else if gradMicros > 180 || standingQueueUs > targetQueueUs*2 {
		backoff := float64(gradMicros) / 4000.0
		if backoff < 0.02 {
			backoff = 0.02
		}
		if backoff > 0.15 {
			backoff = 0.15
		}
		p.rateBps = p.rateBps * (1.0 - backoff)
	}

	if p.rateBps < p.minRateBps {
		p.rateBps = p.minRateBps
	}
	if p.rateBps > p.maxRateBps {
		p.rateBps = p.maxRateBps
	}
}

func (p *MicroPacer) CurrentMBps() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rateBps / (1024 * 1024)
}

// ============================================================================
// Module 5: Gilbert-Elliott Burst-Loss Chaos Simulator
// ============================================================================

type ChaosSimulator struct {
	mu           sync.Mutex
	enabled      bool
	baseLossProb float64
	burstLength  int
	inBurst      int
	rngState     uint64
	droppedCount uint64
}

func NewChaosSimulator(lossRate float64, burstLen int) *ChaosSimulator {
	if lossRate <= 0 {
		return &ChaosSimulator{enabled: false}
	}
	if burstLen < 1 {
		burstLen = 1
	}
	return &ChaosSimulator{
		enabled:      true,
		baseLossProb: lossRate / float64(burstLen),
		burstLength:  burstLen,
		rngState:     cryptoRandUint64() | 1,
	}
}

func (c *ChaosSimulator) ShouldDrop() bool {
	if !c.enabled {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.inBurst > 0 {
		c.inBurst--
		c.droppedCount++
		return true
	}
	r := float64(splitMix64Next(&c.rngState)&0xFFFFFF) / float64(0x1000000)
	if r < c.baseLossProb {
		c.inBurst = c.burstLength - 1
		c.droppedCount++
		return true
	}
	return false
}

// ============================================================================
// Deterministic Chunk Geometry & Socket Helpers
// ============================================================================

func expectedChunkLen(idx, totalChunks uint32, fileSize int64, chunkSize int) int {
	if totalChunks == 0 || idx >= totalChunks {
		return 0
	}
	if idx < totalChunks-1 {
		return chunkSize
	}
	rem := int(fileSize - int64(totalChunks-1)*int64(chunkSize))
	if rem < 0 {
		return 0
	}
	return rem
}

func tuneUDPConn(conn *net.UDPConn) {
	_ = conn.SetReadBuffer(SocketBufferBytes)
	_ = conn.SetWriteBuffer(SocketBufferBytes)
}

// ============================================================================
// Module 6: OpenFIR Receiver Engine (Multi-Core Pipeline + L1 Ring Cache)
// ============================================================================

type ParityEquation struct {
	members    []uint32
	xorPayload []byte
}

type l1CacheSlot struct {
	valid bool
	idx   uint32
	data  []byte
}

type ReceiverSession struct {
	mu               sync.Mutex
	transferID       uint64
	fileName         string
	fileSize         int64
	chunkSize        int
	totalChunks      uint32
	flags            uint8
	expectedSHA256   [32]byte
	file             *os.File
	stagingPath      string
	finalOutputPath  string
	receivedBitmap   []bool
	receivedCount    uint32
	highestContig    uint32
	completed        bool
	verifiedOK       bool
	kalman           *KalmanOWDTracker
	pendingEquations []*ParityEquation
	pendingTeleports map[uint32][]uint32
	l1Cache          [L1ChunkCacheSize]l1CacheSlot
	peers            []*net.UDPAddr
	feedbackTurn     uint64

	// Telemetry counters
	statsDataChunks     uint64
	statsTeleportChunks uint64
	statsParityHealed   uint64
	statsDuplicatePkts  uint64
	startTime           time.Time
}

func (sess *ReceiverSession) cacheChunkLocked(idx uint32, data []byte) {
	slot := &sess.l1Cache[idx%L1ChunkCacheSize]
	if cap(slot.data) < len(data) {
		slot.data = make([]byte, len(data))
	} else {
		slot.data = slot.data[:len(data)]
	}
	copy(slot.data, data)
	slot.idx = idx
	slot.valid = true
}

func (sess *ReceiverSession) readChunkFast(idx uint32, dst []byte) bool {
	expLen := expectedChunkLen(idx, sess.totalChunks, sess.fileSize, sess.chunkSize)
	if len(dst) < expLen {
		return false
	}

	// Check L1 in-memory ring cache first to avoid disk ReadAt syscalls
	sess.mu.Lock()
	slot := &sess.l1Cache[idx%L1ChunkCacheSize]
	if slot.valid && slot.idx == idx && len(slot.data) == expLen {
		copy(dst[:expLen], slot.data)
		sess.mu.Unlock()
		return true
	}
	sess.mu.Unlock()

	n, err := sess.file.ReadAt(dst[:expLen], int64(idx)*int64(sess.chunkSize))
	if err != nil && err != io.EOF {
		return false
	}
	return n == expLen
}

func (sess *ReceiverSession) registerPeer(peer *net.UDPAddr) {
	if peer == nil {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	for _, existing := range sess.peers {
		if existing.IP.Equal(peer.IP) && existing.Port == peer.Port {
			return
		}
	}
	copied := &net.UDPAddr{
		IP:   append([]byte(nil), peer.IP...),
		Port: peer.Port,
		Zone: peer.Zone,
	}
	if len(sess.peers) >= MaxTrackedPeers {
		sess.peers = append(sess.peers[1:], copied)
	} else {
		sess.peers = append(sess.peers, copied)
	}
}

func (sess *ReceiverSession) nextFeedbackPeer(fallback *net.UDPAddr) *net.UDPAddr {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(sess.peers) == 0 {
		return fallback
	}
	idx := sess.feedbackTurn % uint64(len(sess.peers))
	sess.feedbackTurn++
	return sess.peers[idx]
}

func (sess *ReceiverSession) allPeers(fallback *net.UDPAddr) []*net.UDPAddr {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(sess.peers) == 0 {
		if fallback != nil {
			return []*net.UDPAddr{fallback}
		}
		return nil
	}
	out := make([]*net.UDPAddr, len(sess.peers))
	copy(out, sess.peers)
	return out
}

type inboundDatagram struct {
	bufPtr *[]byte
	n      int
	peer   *net.UDPAddr
}

type OpenFIRServer struct {
	conn      *net.UDPConn
	outputDir string
	secret    uint64
	saltGen   uint64

	mu       sync.Mutex
	sessions map[uint64]*ReceiverSession
	doneChan chan struct{}
}

func NewOpenFIRServer(listenAddr, outputDir string, secret uint64) (*OpenFIRServer, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	tuneUDPConn(conn)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &OpenFIRServer{
		conn:      conn,
		outputDir: outputDir,
		secret:    secret,
		saltGen:   cryptoRandUint64(),
		sessions:  make(map[uint64]*ReceiverSession),
		doneChan:  make(chan struct{}),
	}, nil
}

func (s *OpenFIRServer) LocalAddr() string {
	return s.conn.LocalAddr().String()
}

func (s *OpenFIRServer) Close() {
	select {
	case <-s.doneChan:
	default:
		close(s.doneChan)
		_ = s.conn.Close()
	}
}

func (s *OpenFIRServer) sendCloaked(raw []byte, peer *net.UDPAddr) {
	if peer == nil {
		return
	}
	seq := atomic.AddUint64(&s.saltGen, 1)
	wire := cloakPacket(raw, s.secret, seq)
	_, _ = s.conn.WriteToUDP(wire, peer)
}

func (s *OpenFIRServer) Serve(exitOnFirstComplete bool) error {
	var activePeer atomic.Value
	var activeSession atomic.Value
	var completeOnce sync.Once
	completedChan := make(chan struct{})

	// Periodic feedback loop: rotates selective NACK bitmap + Kalman OWDG across client paths
	feedbackDone := make(chan struct{})
	defer close(feedbackDone)
	go func() {
		ticker := time.NewTicker(15 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.doneChan:
				return
			case <-feedbackDone:
				return
			case <-ticker.C:
				peerVal := activePeer.Load()
				sessVal := activeSession.Load()
				if peerVal != nil && sessVal != nil {
					fallbackPeer := peerVal.(*net.UDPAddr)
					sess := sessVal.(*ReceiverSession)
					targetPeer := sess.nextFeedbackPeer(fallbackPeer)
					s.sendFeedback(sess, targetPeer)
				}
			}
		}
	}()

	// Multi-core worker pool for parallel AES-256-GCM decryption & disk commits
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	if numWorkers > 16 {
		numWorkers = 16
	}
	workQueue := make(chan inboundDatagram, 4096)
	var workerWG sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for item := range workQueue {
				raw, ok := uncloakPacket((*item.bufPtr)[:item.n], s.secret)
				packetBufferPool.Put(item.bufPtr)
				if !ok || len(raw) < 3 {
					continue
				}

				pktType := raw[2]
				payload := raw[3:]
				peer := item.peer

				switch pktType {
				case PktHandshake:
					sess, err := s.handleHandshake(payload, peer)
					if err == nil && sess != nil {
						sess.registerPeer(peer)
						activePeer.Store(peer)
						activeSession.Store(sess)
						if sess.totalChunks == 0 && sess.checkAndFinalize(s, peer) && exitOnFirstComplete {
							completeOnce.Do(func() { close(completedChan) })
						}
					}

				case PktData:
					sessVal := activeSession.Load()
					if sessVal == nil {
						continue
					}
					sess := sessVal.(*ReceiverSession)
					sess.registerPeer(peer)
					activePeer.Store(peer)
					s.handleData(sess, payload)
					if sess.checkAndFinalize(s, peer) && exitOnFirstComplete {
						completeOnce.Do(func() { close(completedChan) })
					}

				case PktTeleport:
					sessVal := activeSession.Load()
					if sessVal == nil {
						continue
					}
					sess := sessVal.(*ReceiverSession)
					sess.registerPeer(peer)
					activePeer.Store(peer)
					s.handleTeleport(sess, payload)
					if sess.checkAndFinalize(s, peer) && exitOnFirstComplete {
						completeOnce.Do(func() { close(completedChan) })
					}

				case PktPhiParity:
					sessVal := activeSession.Load()
					if sessVal == nil {
						continue
					}
					sess := sessVal.(*ReceiverSession)
					sess.registerPeer(peer)
					activePeer.Store(peer)
					s.handlePhiParity(sess, payload)
					if sess.checkAndFinalize(s, peer) && exitOnFirstComplete {
						completeOnce.Do(func() { close(completedChan) })
					}

				case PktFin:
					sessVal := activeSession.Load()
					if sessVal == nil {
						continue
					}
					sess := sessVal.(*ReceiverSession)
					sess.registerPeer(peer)
					if sess.checkAndFinalize(s, peer) && exitOnFirstComplete {
						completeOnce.Do(func() { close(completedChan) })
					} else {
						s.sendFeedback(sess, peer)
					}
				}
			}
		}()
	}

	defer func() {
		close(workQueue)
		workerWG.Wait()
	}()

	for {
		select {
		case <-completedChan:
			return nil
		case <-s.doneChan:
			return nil
		default:
		}

		_ = s.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		bufPtr := packetBufferPool.Get().(*[]byte)
		n, peer, err := s.conn.ReadFromUDP(*bufPtr)
		if err != nil {
			packetBufferPool.Put(bufPtr)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.doneChan:
				return nil
			case <-completedChan:
				return nil
			default:
				return err
			}
		}

		workQueue <- inboundDatagram{
			bufPtr: bufPtr,
			n:      n,
			peer:   peer,
		}
	}
}

func (s *OpenFIRServer) handleHandshake(p []byte, peer *net.UDPAddr) (*ReceiverSession, error) {
	// Layout: [8B TxID][8B FileSize][4B ChunkSize][4B TotalChunks][32B SHA256][1B Flags][2B NameLen][NameBytes]
	if len(p) < 59 {
		return nil, errors.New("short handshake frame")
	}
	transferID := binary.BigEndian.Uint64(p[0:8])
	fileSize := int64(binary.BigEndian.Uint64(p[8:16]))
	chunkSize := int(binary.BigEndian.Uint32(p[16:20]))
	totalChunks := binary.BigEndian.Uint32(p[20:24])
	var expectedHash [32]byte
	copy(expectedHash[:], p[24:56])
	flags := p[56]
	nameLen := int(binary.BigEndian.Uint16(p[57:59]))
	if len(p) < 59+nameLen {
		return nil, errors.New("invalid filename length in handshake")
	}
	fileName := filepath.Base(string(p[59 : 59+nameLen]))

	s.mu.Lock()
	sess, exists := s.sessions[transferID]
	if !exists {
		finalOutPath := filepath.Join(s.outputDir, fileName)
		stagingPath := finalOutPath
		if flags == FlagDirectoryBundle {
			stagingPath = filepath.Join(s.outputDir, fmt.Sprintf(".openfir_bundle_%x.tmp", transferID))
		}

		f, err := os.OpenFile(stagingPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if fileSize > 0 {
			_ = f.Truncate(fileSize)
		}
		sess = &ReceiverSession{
			transferID:       transferID,
			fileName:         fileName,
			fileSize:         fileSize,
			chunkSize:        chunkSize,
			totalChunks:      totalChunks,
			flags:            flags,
			expectedSHA256:   expectedHash,
			file:             f,
			stagingPath:      stagingPath,
			finalOutputPath:  finalOutPath,
			receivedBitmap:   make([]bool, totalChunks),
			kalman:           NewKalmanOWDTracker(),
			pendingTeleports: make(map[uint32][]uint32),
			startTime:        time.Now(),
		}
		s.sessions[transferID] = sess
		modeStr := "SingleFile"
		if flags == FlagDirectoryBundle {
			modeStr = "DirectoryBundle"
		}
		fmt.Printf("[Server] Session initialized (%s): target=%s size=%d bytes chunks=%d\n",
			modeStr, fileName, fileSize, totalChunks)
	}
	s.mu.Unlock()

	ack := make([]byte, 15)
	ack[0] = ProtocolMagic0
	ack[1] = ProtocolMagic1
	ack[2] = PktHandshakeAck
	binary.BigEndian.PutUint64(ack[3:11], transferID)
	sess.mu.Lock()
	hc := sess.highestContig
	sess.mu.Unlock()
	binary.BigEndian.PutUint32(ack[11:15], hc)
	s.sendCloaked(ack, peer)

	return sess, nil
}

func (s *OpenFIRServer) handleData(sess *ReceiverSession, p []byte) {
	if len(p) < 14 {
		return
	}
	idx := binary.BigEndian.Uint32(p[0:4])
	sendNano := int64(binary.BigEndian.Uint64(p[4:12]))
	dataLen := int(binary.BigEndian.Uint16(p[12:14]))
	if len(p) < 14+dataLen {
		return
	}
	sess.kalman.Observe(sendNano, time.Now().UnixNano())
	sess.commitChunk(idx, p[14:14+dataLen], "data")
}

func (s *OpenFIRServer) handleTeleport(sess *ReceiverSession, p []byte) {
	if len(p) < 16 {
		return
	}
	targetIdx := binary.BigEndian.Uint32(p[0:4])
	sourceIdx := binary.BigEndian.Uint32(p[4:8])
	sendNano := int64(binary.BigEndian.Uint64(p[8:16]))

	sess.kalman.Observe(sendNano, time.Now().UnixNano())

	if targetIdx >= sess.totalChunks || sourceIdx >= sess.totalChunks {
		return
	}

	sess.mu.Lock()
	if sess.receivedBitmap[targetIdx] {
		sess.mu.Unlock()
		return
	}
	hasSource := sess.receivedBitmap[sourceIdx]
	if !hasSource {
		sess.pendingTeleports[sourceIdx] = append(sess.pendingTeleports[sourceIdx], targetIdx)
		sess.mu.Unlock()
		return
	}
	sess.mu.Unlock()

	expLen := expectedChunkLen(targetIdx, sess.totalChunks, sess.fileSize, sess.chunkSize)
	buf := make([]byte, expLen)
	if sess.readChunkFast(sourceIdx, buf) {
		sess.commitChunk(targetIdx, buf, "teleport")
	}
}

func (s *OpenFIRServer) handlePhiParity(sess *ReceiverSession, p []byte) {
	if len(p) < 3 {
		return
	}
	count := int(p[0])
	if count < 2 || count > 8 || len(p) < 1+count*4+2 {
		return
	}
	members := make([]uint32, count)
	offset := 1
	for i := 0; i < count; i++ {
		members[i] = binary.BigEndian.Uint32(p[offset : offset+4])
		offset += 4
	}
	parityLen := int(binary.BigEndian.Uint16(p[offset : offset+2]))
	offset += 2
	if len(p) < offset+parityLen {
		return
	}
	xorPayload := make([]byte, parityLen)
	copy(xorPayload, p[offset:offset+parityLen])

	eq := &ParityEquation{
		members:    members,
		xorPayload: xorPayload,
	}
	sess.processOrEnqueueEquation(eq)
}

func (sess *ReceiverSession) commitChunk(idx uint32, data []byte, source string) {
	if idx >= sess.totalChunks {
		return
	}
	expLen := expectedChunkLen(idx, sess.totalChunks, sess.fileSize, sess.chunkSize)
	if len(data) < expLen {
		return
	}
	if len(data) > expLen {
		data = data[:expLen]
	}

	sess.mu.Lock()
	if sess.receivedBitmap[idx] {
		sess.statsDuplicatePkts++
		sess.mu.Unlock()
		return
	}
	sess.mu.Unlock()

	offset := int64(idx) * int64(sess.chunkSize)
	if _, err := sess.file.WriteAt(data, offset); err != nil {
		return
	}

	sess.mu.Lock()
	if sess.receivedBitmap[idx] {
		sess.mu.Unlock()
		return
	}
	sess.receivedBitmap[idx] = true
	sess.receivedCount++
	sess.cacheChunkLocked(idx, data)

	switch source {
	case "data":
		sess.statsDataChunks++
	case "teleport":
		sess.statsTeleportChunks++
	case "parity":
		sess.statsParityHealed++
	}
	for sess.highestContig < sess.totalChunks && sess.receivedBitmap[sess.highestContig] {
		sess.highestContig++
	}

	waitingTeleports := sess.pendingTeleports[idx]
	delete(sess.pendingTeleports, idx)

	var readyEquations []*ParityEquation
	if len(sess.pendingEquations) > 0 {
		remaining := sess.pendingEquations[:0]
		for _, eq := range sess.pendingEquations {
			missingCount := 0
			for _, m := range eq.members {
				if m < sess.totalChunks && !sess.receivedBitmap[m] {
					missingCount++
				}
			}
			if missingCount == 0 {
				continue
			} else if missingCount == 1 {
				readyEquations = append(readyEquations, eq)
			} else {
				remaining = append(remaining, eq)
			}
		}
		sess.pendingEquations = remaining
	}
	sess.mu.Unlock()

	for _, targetIdx := range waitingTeleports {
		sess.commitChunk(targetIdx, data, "teleport")
	}

	for _, eq := range readyEquations {
		sess.healSingleMissingEquation(eq)
	}
}

func (sess *ReceiverSession) processOrEnqueueEquation(eq *ParityEquation) {
	sess.mu.Lock()
	missingCount := 0
	for _, m := range eq.members {
		if m < sess.totalChunks && !sess.receivedBitmap[m] {
			missingCount++
		}
	}
	if missingCount == 0 {
		sess.mu.Unlock()
		return
	}
	if missingCount > 1 {
		if len(sess.pendingEquations) >= MaxPendingParity {
			sess.pendingEquations = sess.pendingEquations[1:]
		}
		sess.pendingEquations = append(sess.pendingEquations, eq)
		sess.mu.Unlock()
		return
	}
	sess.mu.Unlock()

	sess.healSingleMissingEquation(eq)
}

func (sess *ReceiverSession) healSingleMissingEquation(eq *ParityEquation) {
	sess.mu.Lock()
	var missingIdx uint32 = math.MaxUint32
	missingCount := 0
	for _, m := range eq.members {
		if m < sess.totalChunks && !sess.receivedBitmap[m] {
			missingIdx = m
			missingCount++
		}
	}
	sess.mu.Unlock()

	if missingCount != 1 || missingIdx == math.MaxUint32 {
		return
	}

	healed := make([]byte, sess.chunkSize)
	copy(healed, eq.xorPayload)
	tmpBuf := make([]byte, sess.chunkSize)

	for _, m := range eq.members {
		if m == missingIdx {
			continue
		}
		expLen := expectedChunkLen(m, sess.totalChunks, sess.fileSize, sess.chunkSize)
		if !sess.readChunkFast(m, tmpBuf[:expLen]) {
			return
		}
		for b := 0; b < expLen; b++ {
			healed[b] ^= tmpBuf[b]
		}
	}

	targetLen := expectedChunkLen(missingIdx, sess.totalChunks, sess.fileSize, sess.chunkSize)
	sess.commitChunk(missingIdx, healed[:targetLen], "parity")
}

func (s *OpenFIRServer) sendFeedback(sess *ReceiverSession, peer *net.UDPAddr) {
	sess.mu.Lock()
	if sess.completed {
		sess.mu.Unlock()
		return
	}
	hc := sess.highestContig
	rc := sess.receivedCount
	total := sess.totalChunks

	var nacks []uint32
	for idx := hc; idx < total && len(nacks) < MaxNackPerPacket; idx++ {
		if !sess.receivedBitmap[idx] {
			nacks = append(nacks, idx)
		}
	}
	sess.mu.Unlock()

	gradUs, queueUs := sess.kalman.Snapshot()

	pkt := make([]byte, 37+len(nacks)*4)
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktFeedback
	binary.BigEndian.PutUint64(pkt[3:11], sess.transferID)
	binary.BigEndian.PutUint32(pkt[11:15], hc)
	binary.BigEndian.PutUint32(pkt[15:19], rc)
	binary.BigEndian.PutUint64(pkt[19:27], uint64(gradUs))
	binary.BigEndian.PutUint64(pkt[27:35], uint64(queueUs))
	binary.BigEndian.PutUint16(pkt[35:37], uint16(len(nacks)))

	offset := 37
	for _, nackIdx := range nacks {
		binary.BigEndian.PutUint32(pkt[offset:offset+4], nackIdx)
		offset += 4
	}
	s.sendCloaked(pkt, peer)
}

func (sess *ReceiverSession) checkAndFinalize(s *OpenFIRServer, fallbackPeer *net.UDPAddr) bool {
	sess.mu.Lock()
	if sess.receivedCount < sess.totalChunks {
		sess.mu.Unlock()
		return false
	}
	alreadyDone := sess.completed
	if !alreadyDone {
		sess.completed = true
		_ = sess.file.Sync()

		_, _ = sess.file.Seek(0, io.SeekStart)
		h := sha256.New()
		_, _ = io.Copy(h, sess.file)
		var actualHash [32]byte
		copy(actualHash[:], h.Sum(nil))
		hashMatch := (actualHash == sess.expectedSHA256)

		extractedFiles := 1
		if hashMatch && sess.flags == FlagDirectoryBundle {
			cnt, err := unpackDirectoryBundle(sess.file, sess.fileSize, sess.finalOutputPath)
			if err != nil {
				hashMatch = false
			} else {
				extractedFiles = cnt
			}
		}
		sess.verifiedOK = hashMatch
		_ = sess.file.Close()
		if sess.flags == FlagDirectoryBundle {
			_ = os.Remove(sess.stagingPath)
		}

		elapsed := time.Since(sess.startTime).Seconds()
		if elapsed <= 0 {
			elapsed = 0.001
		}
		mbps := (float64(sess.fileSize) / (1024 * 1024)) / elapsed
		fmt.Printf("\n====================================================================\n")
		fmt.Printf("[Server] Transfer Complete! Target: %s (%.2f MB, %d file(s))\n",
			sess.finalOutputPath, float64(sess.fileSize)/(1024*1024), extractedFiles)
		fmt.Printf("  ├─ Elapsed & Goodput : %.3f s (Effective Goodput: %.2f MB/s)\n", elapsed, mbps)
		fmt.Printf("  ├─ Chunk Breakdown   : Data=%d | Teleported=%d | PhiParityHealed=%d\n",
			sess.statsDataChunks, sess.statsTeleportChunks, sess.statsParityHealed)
		fmt.Printf("  └─ SHA-256 Verified  : %v (%s...)\n", sess.verifiedOK, hex.EncodeToString(actualHash[:8]))
		fmt.Printf("====================================================================\n")
	}
	verified := sess.verifiedOK
	tid := sess.transferID
	sess.mu.Unlock()

	finAck := make([]byte, 12)
	finAck[0] = ProtocolMagic0
	finAck[1] = ProtocolMagic1
	finAck[2] = PktFinAck
	binary.BigEndian.PutUint64(finAck[3:11], tid)
	if verified {
		finAck[11] = 1
	} else {
		finAck[11] = 0
	}

	peers := sess.allPeers(fallbackPeer)
	for round := 0; round < 3; round++ {
		for _, p := range peers {
			s.sendCloaked(finAck, p)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return true
}

// ============================================================================
// Module 7: OpenFIR Multi-Path Sender Engine (Single File + Directory Extent)
// ============================================================================

type OpenFIRClient struct {
	conns      []*net.UDPConn
	serverAddr *net.UDPAddr
	secret     uint64
	saltGen    uint64
	pacer      *MicroPacer
	chaos      *ChaosSimulator
}

func NewOpenFIRClient(serverAddrStr string, secret uint64, numSockets int, initMBps, maxMBps float64, chaos *ChaosSimulator) (*OpenFIRClient, error) {
	if numSockets < 1 {
		numSockets = 1
	}
	if numSockets > 64 {
		numSockets = 64
	}
	raddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		return nil, err
	}
	conns := make([]*net.UDPConn, 0, numSockets)
	for i := 0; i < numSockets; i++ {
		laddr, err := net.ResolveUDPAddr("udp", ":0")
		if err != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, err
		}
		conn, err := net.ListenUDP("udp", laddr)
		if err != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, err
		}
		tuneUDPConn(conn)
		conns = append(conns, conn)
	}
	return &OpenFIRClient{
		conns:      conns,
		serverAddr: raddr,
		secret:     secret,
		saltGen:    cryptoRandUint64(),
		pacer:      NewMicroPacer(initMBps, 2.0, maxMBps),
		chaos:      chaos,
	}, nil
}

func (c *OpenFIRClient) Close() {
	for _, conn := range c.conns {
		_ = conn.Close()
	}
}

func (c *OpenFIRClient) sendCloaked(raw []byte) {
	if c.chaos != nil && c.chaos.ShouldDrop() {
		return
	}
	seq := atomic.AddUint64(&c.saltGen, 1)
	wire := cloakPacket(raw, c.secret, seq)
	connIdx := int(seq % uint64(len(c.conns)))
	_, _ = c.conns[connIdx].WriteToUDP(wire, c.serverAddr)
}

func computeExtentSHA256(r io.ReaderAt, totalSize int64) ([32]byte, error) {
	h := sha256.New()
	buf := make([]byte, 256*1024)
	var offset int64 = 0
	for offset < totalSize {
		step := int64(len(buf))
		if totalSize-offset < step {
			step = totalSize - offset
		}
		n, err := r.ReadAt(buf[:step], offset)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			offset += int64(n)
		}
		if err != nil && err != io.EOF {
			return [32]byte{}, err
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func (c *OpenFIRClient) SendFile(targetPath string) error {
	stat, err := os.Stat(targetPath)
	if err != nil {
		return err
	}

	var readerAt io.ReaderAt
	var closer io.Closer
	var totalSize int64
	var flags uint8
	var fileCount int = 1

	if stat.IsDir() {
		ext, err := NewVirtualDirectoryExtent(targetPath)
		if err != nil {
			return err
		}
		readerAt = ext
		closer = ext
		totalSize = ext.Size()
		flags = FlagDirectoryBundle
		fileCount = ext.FileCount()
	} else {
		f, err := os.Open(targetPath)
		if err != nil {
			return err
		}
		readerAt = f
		closer = f
		totalSize = stat.Size()
		flags = FlagSingleFile
	}
	defer closer.Close()

	chunkSize := DefaultChunkSize
	totalChunks := uint32((totalSize + int64(chunkSize) - 1) / int64(chunkSize))
	if totalSize == 0 {
		totalChunks = 0
	}

	streamSHA256, err := computeExtentSHA256(readerAt, totalSize)
	if err != nil {
		return err
	}

	rndInt, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	transferID := uint64(rndInt.Int64())
	baseName := filepath.Base(filepath.Clean(targetPath))

	fmt.Printf("[Client] Starting OpenFIR transfer: %s (%.2f MB, %d file(s), %d chunks, %d UDP paths)\n",
		baseName, float64(totalSize)/(1024*1024), fileCount, totalChunks, len(c.conns))

	var stateMu sync.Mutex
	ackedBitmap := make([]bool, totalChunks)
	var highestContig uint32
	retransmitQueue := make([]uint32, 0, 1024)
	inRetransQueue := make([]bool, totalChunks)
	handshakeDone := false
	transferFinAcked := false
	remoteVerified := false

	stopRecv := make(chan struct{})
	var recvWG sync.WaitGroup
	for _, sock := range c.conns {
		recvWG.Add(1)
		go func(conn *net.UDPConn) {
			defer recvWG.Done()
			buf := make([]byte, MaxUDPPacketSize+256)
			for {
				select {
				case <-stopRecv:
					return
				default:
				}
				_ = conn.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
				n, _, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				raw, ok := uncloakPacket(buf[:n], c.secret)
				if !ok || len(raw) < 3 {
					continue
				}
				pktType := raw[2]
				p := raw[3:]

				switch pktType {
				case PktHandshakeAck:
					if len(p) >= 12 && binary.BigEndian.Uint64(p[0:8]) == transferID {
						stateMu.Lock()
						handshakeDone = true
						stateMu.Unlock()
					}

				case PktFeedback:
					if len(p) < 34 || binary.BigEndian.Uint64(p[0:8]) != transferID {
						continue
					}
					hc := binary.BigEndian.Uint32(p[8:12])
					gradUs := int64(binary.BigEndian.Uint64(p[16:24]))
					queueUs := int64(binary.BigEndian.Uint64(p[24:32]))
					nackCount := int(binary.BigEndian.Uint16(p[32:34]))

					c.pacer.UpdateFromKalman(gradUs, queueUs)

					stateMu.Lock()
					handshakeDone = true
					if hc > highestContig {
						for idx := highestContig; idx < hc && idx < totalChunks; idx++ {
							ackedBitmap[idx] = true
						}
						highestContig = hc
					}

					offset := 34
					for i := 0; i < nackCount && offset+4 <= len(p); i++ {
						nackIdx := binary.BigEndian.Uint32(p[offset : offset+4])
						offset += 4
						if nackIdx < totalChunks && !ackedBitmap[nackIdx] && !inRetransQueue[nackIdx] {
							inRetransQueue[nackIdx] = true
							retransmitQueue = append(retransmitQueue, nackIdx)
						}
					}
					stateMu.Unlock()

				case PktFinAck:
					if len(p) >= 9 && binary.BigEndian.Uint64(p[0:8]) == transferID {
						stateMu.Lock()
						handshakeDone = true
						transferFinAcked = true
						remoteVerified = (p[8] == 1)
						stateMu.Unlock()
					}
				}
			}
		}(sock)
	}
	defer func() {
		close(stopRecv)
		recvWG.Wait()
	}()

	// Phase 1: Handshake synchronization
	hsPkt := buildHandshakePacket(transferID, totalSize, chunkSize, totalChunks, streamSHA256, flags, baseName)
	for i := 0; i < 60; i++ {
		stateMu.Lock()
		done := handshakeDone
		stateMu.Unlock()
		if done {
			break
		}
		c.sendCloaked(hsPkt)
		time.Sleep(40 * time.Millisecond)
	}

	contentHashToChunk := make(map[[32]byte]uint32)
	var teleportSentCount uint64
	var phiParitySentCount uint64

	windowChunks := make([][]byte, PhiWindowSize)
	windowIndices := make([]uint32, PhiWindowSize)
	windowFill := 0
	tailParityFlushed := false

	// 256 KB sequential read-ahead buffer to minimize OS read syscalls during first pass
	const readAheadBytes = 200 * DefaultChunkSize
	readAheadBuf := make([]byte, readAheadBytes)
	var readAheadStart int64 = -1
	var readAheadValid int64 = 0

	readChunkSequential := func(idx uint32, dst []byte) (int, error) {
		byteOff := int64(idx) * int64(chunkSize)
		expLen := len(dst)
		if byteOff >= readAheadStart && byteOff+int64(expLen) <= readAheadStart+readAheadValid {
			rel := int(byteOff - readAheadStart)
			copy(dst, readAheadBuf[rel:rel+expLen])
			return expLen, nil
		}
		n, err := readerAt.ReadAt(readAheadBuf, byteOff)
		if n > 0 {
			readAheadStart = byteOff
			readAheadValid = int64(n)
			if n >= expLen {
				copy(dst, readAheadBuf[:expLen])
				return expLen, nil
			}
		}
		return readerAt.ReadAt(dst, byteOff)
	}

	var nextChunk uint32 = 0
	var sweepCursor uint32 = 0
	readBuf := make([]byte, chunkSize)

	// Phase 2: Main transmission & selective repeat loop
	for {
		stateMu.Lock()
		finAcked := transferFinAcked
		verified := remoteVerified
		hc := highestContig
		var nackIdx uint32 = math.MaxUint32
		if len(retransmitQueue) > 0 {
			nackIdx = retransmitQueue[0]
			retransmitQueue = retransmitQueue[1:]
			inRetransQueue[nackIdx] = false
		}
		stateMu.Unlock()

		if finAcked {
			if !verified {
				return errors.New("end-to-end SHA-256 verification failed on receiver")
			}
			fmt.Printf("[Client] Transfer 100%% verified! (TeleportCmds=%d, PhiParityFrames=%d, Rate=%.2f MB/s)\n",
				teleportSentCount, phiParitySentCount, c.pacer.CurrentMBps())
			return nil
		}

		// Priority 1: Service explicit NACK retransmissions (strictly using raw PktData)
		if nackIdx != math.MaxUint32 && nackIdx >= hc {
			expLen := expectedChunkLen(nackIdx, totalChunks, totalSize, chunkSize)
			n, err := readerAt.ReadAt(readBuf[:expLen], int64(nackIdx)*int64(chunkSize))
			if err == nil || err == io.EOF {
				pkt := buildDataPacket(nackIdx, readBuf[:n])
				c.pacer.Wait(len(pkt))
				c.sendCloaked(pkt)
			}
			continue
		}

		// Priority 2: First-pass transmission (with Teleportation & Phi-Parity interleaving)
		if nextChunk < totalChunks {
			idx := nextChunk
			nextChunk++

			expLen := expectedChunkLen(idx, totalChunks, totalSize, chunkSize)
			n, err := readChunkSequential(idx, readBuf[:expLen])
			if err != nil && err != io.EOF {
				return err
			}
			chunkData := make([]byte, n)
			copy(chunkData, readBuf[:n])

			chunkHash := sha256.Sum256(chunkData)
			prevIdx, seenBefore := contentHashToChunk[chunkHash]
			if !seenBefore {
				contentHashToChunk[chunkHash] = idx
			}

			if seenBefore && prevIdx < idx {
				tpPkt := buildTeleportPacket(idx, prevIdx)
				c.pacer.Wait(len(tpPkt))
				c.sendCloaked(tpPkt)
				teleportSentCount++
			} else {
				dataPkt := buildDataPacket(idx, chunkData)
				c.pacer.Wait(len(dataPkt))
				c.sendCloaked(dataPkt)
			}

			padded := make([]byte, chunkSize)
			copy(padded, chunkData)
			windowChunks[windowFill] = padded
			windowIndices[windowFill] = idx
			windowFill++

			if windowFill == PhiWindowSize {
				for bucket := 0; bucket < PhiStride; bucket++ {
					members := make([]uint32, PhiGroupMembers)
					xorPayload := make([]byte, chunkSize)
					for m := 0; m < PhiGroupMembers; m++ {
						pos := bucket + m*PhiStride
						members[m] = windowIndices[pos]
						for b := 0; b < chunkSize; b++ {
							xorPayload[b] ^= windowChunks[pos][b]
						}
					}
					parityPkt := buildPhiParityPacket(members, xorPayload)
					c.pacer.Wait(len(parityPkt))
					c.sendCloaked(parityPkt)
					phiParitySentCount++
				}
				windowFill = 0
			}
			continue
		}

		// Flush remaining tail window parity if partially filled
		if !tailParityFlushed {
			tailParityFlushed = true
			if windowFill >= 2 {
				half := windowFill / 2
				for i := 0; i < half; i++ {
					members := []uint32{windowIndices[i], windowIndices[i+half]}
					xorPayload := make([]byte, chunkSize)
					for b := 0; b < chunkSize; b++ {
						xorPayload[b] = windowChunks[i][b] ^ windowChunks[i+half][b]
					}
					parityPkt := buildPhiParityPacket(members, xorPayload)
					c.pacer.Wait(len(parityPkt))
					c.sendCloaked(parityPkt)
					phiParitySentCount++
				}
				windowFill = 0
			}
		}

		// Priority 3: Tail convergence sweep & completion synchronization
		if hc < totalChunks {
			if sweepCursor < hc || sweepCursor >= totalChunks {
				sweepCursor = hc
			}
			stateMu.Lock()
			alreadyAcked := ackedBitmap[sweepCursor]
			stateMu.Unlock()

			if !alreadyAcked {
				expLen := expectedChunkLen(sweepCursor, totalChunks, totalSize, chunkSize)
				n, err := readerAt.ReadAt(readBuf[:expLen], int64(sweepCursor)*int64(chunkSize))
				if err == nil || err == io.EOF {
					pkt := buildDataPacket(sweepCursor, readBuf[:n])
					c.pacer.Wait(len(pkt))
					c.sendCloaked(pkt)
				}
			}
			sweepCursor++
		} else {
			finPkt := make([]byte, 11)
			finPkt[0] = ProtocolMagic0
			finPkt[1] = ProtocolMagic1
			finPkt[2] = PktFin
			binary.BigEndian.PutUint64(finPkt[3:11], transferID)
			c.sendCloaked(finPkt)
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// ============================================================================
// Wire Frame Builders
// ============================================================================

func buildHandshakePacket(tid uint64, fileSize int64, chunkSize int, totalChunks uint32, sha [32]byte, flags uint8, name string) []byte {
	nameBytes := []byte(name)
	pkt := make([]byte, 3+59+len(nameBytes))
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktHandshake
	binary.BigEndian.PutUint64(pkt[3:11], tid)
	binary.BigEndian.PutUint64(pkt[11:19], uint64(fileSize))
	binary.BigEndian.PutUint32(pkt[19:23], uint32(chunkSize))
	binary.BigEndian.PutUint32(pkt[23:27], totalChunks)
	copy(pkt[27:59], sha[:])
	pkt[59] = flags
	binary.BigEndian.PutUint16(pkt[60:62], uint16(len(nameBytes)))
	copy(pkt[62:], nameBytes)
	return pkt
}

func buildDataPacket(idx uint32, data []byte) []byte {
	pkt := make([]byte, 3+14+len(data))
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktData
	binary.BigEndian.PutUint32(pkt[3:7], idx)
	binary.BigEndian.PutUint64(pkt[7:15], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(pkt[15:17], uint16(len(data)))
	copy(pkt[17:], data)
	return pkt
}

func buildTeleportPacket(targetIdx, sourceIdx uint32) []byte {
	pkt := make([]byte, 3+16)
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktTeleport
	binary.BigEndian.PutUint32(pkt[3:7], targetIdx)
	binary.BigEndian.PutUint32(pkt[7:11], sourceIdx)
	binary.BigEndian.PutUint64(pkt[11:19], uint64(time.Now().UnixNano()))
	return pkt
}

func buildPhiParityPacket(members []uint32, xorPayload []byte) []byte {
	count := len(members)
	pkt := make([]byte, 3+1+count*4+2+len(xorPayload))
	pkt[0] = ProtocolMagic0
	pkt[1] = ProtocolMagic1
	pkt[2] = PktPhiParity
	pkt[3] = uint8(count)
	offset := 4
	for _, m := range members {
		binary.BigEndian.PutUint32(pkt[offset:offset+4], m)
		offset += 4
	}
	binary.BigEndian.PutUint16(pkt[offset:offset+2], uint16(len(xorPayload)))
	offset += 2
	copy(pkt[offset:], xorPayload)
	return pkt
}

// ============================================================================
// Module 8: Automated Chaos Self-Test Engine (-mode selftest)
// Validates BOTH:
//   1) A 16 MB mixed-entropy single file under Gilbert-Elliott burst packet loss
//   2) A nested directory tree of 200 small files via Zero-RTT Virtual Extent
// ============================================================================

func runSelfTest(lossRate float64, burstLen int, numSockets int) error {
	fmt.Printf("====================================================================\n")
	fmt.Printf("  OpenFIR Automated Chaos Self-Test Engine\n")
	fmt.Printf("  Injected Channel Conditions: LossRate=%.1f%% | MeanBurstLength=%d | Sockets=%d\n",
		lossRate*100, burstLen, numSockets)
	fmt.Printf("====================================================================\n")

	tmpDir, err := os.MkdirTemp("", "openfir_selftest_*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	const sharedSecret uint64 = 0xA37F92C819E4B50D
	outDir := filepath.Join(tmpDir, "received")

	// ------------------------------------------------------------------------
	// Test Suite 1: 16 MB Mixed-Entropy Single Large File
	// ------------------------------------------------------------------------
	fmt.Printf("\n--- [Suite 1/2] Single Large File Transfer (16.00 MB) ---\n")
	srcFile := filepath.Join(tmpDir, "test_payload.bin")
	const totalTestBytes = 16 * 1024 * 1024
	rawFileBytes := make([]byte, totalTestBytes)
	patternBlock := make([]byte, 64*1024)
	_, _ = rand.Read(patternBlock)

	offset := 0
	for offset < totalTestBytes {
		if (offset/(64*1024))%3 == 0 {
			copy(rawFileBytes[offset:], patternBlock)
		} else {
			_, _ = rand.Read(rawFileBytes[offset : offset+64*1024])
		}
		offset += 64 * 1024
	}
	if err := os.WriteFile(srcFile, rawFileBytes, 0644); err != nil {
		return err
	}

	srv1, err := NewOpenFIRServer("127.0.0.1:0", outDir, sharedSecret)
	if err != nil {
		return err
	}
	srv1Err := make(chan error, 1)
	go func() { srv1Err <- srv1.Serve(true) }()

	chaos1 := NewChaosSimulator(lossRate, burstLen)
	cli1, err := NewOpenFIRClient(srv1.LocalAddr(), sharedSecret, numSockets, 80.0, 500.0, chaos1)
	if err != nil {
		srv1.Close()
		return err
	}
	if err := cli1.SendFile(srcFile); err != nil {
		cli1.Close()
		srv1.Close()
		return err
	}
	cli1.Close()
	if err := <-srv1Err; err != nil {
		srv1.Close()
		return err
	}
	srv1.Close()

	dstFile := filepath.Join(outDir, "test_payload.bin")
	receivedBytes, err := os.ReadFile(dstFile)
	if err != nil {
		return err
	}
	if !bytes.Equal(rawFileBytes, receivedBytes) {
		return errors.New("suite 1 failure: received large file does not match source byte-for-byte")
	}

	// ------------------------------------------------------------------------
	// Test Suite 2: 200 Small Files Across Nested Subdirectories (Zero-RTT Extent)
	// ------------------------------------------------------------------------
	fmt.Printf("\n--- [Suite 2/2] Massive Small-Files Directory Tree (200 files) ---\n")
	srcSmallDir := filepath.Join(tmpDir, "small_files_dataset")
	expectedSmallFiles := make(map[string][]byte)
	sharedSmallTemplate := make([]byte, 4096)
	_, _ = rand.Read(sharedSmallTemplate)

	for i := 0; i < 200; i++ {
		subDir := filepath.Join(srcSmallDir, fmt.Sprintf("module_%02d", i%10), fmt.Sprintf("layer_%02d", i%4))
		if err := os.MkdirAll(subDir, 0755); err != nil {
			return err
		}
		fName := fmt.Sprintf("asset_%03d.dat", i)
		fullPath := filepath.Join(subDir, fName)

		var content []byte
		switch {
		case i%5 == 0:
			// Identical cross-file content to exercise cross-file Teleportation
			content = append([]byte(nil), sharedSmallTemplate...)
		case i%17 == 0:
			// Tiny micro-file (37 bytes) to exercise micro-file chunk coalescing
			content = make([]byte, 37)
			_, _ = rand.Read(content)
		default:
			sz := 300 + (i*97)%8192
			content = make([]byte, sz)
			_, _ = rand.Read(content)
		}
		if err := os.WriteFile(fullPath, content, 0644); err != nil {
			return err
		}
		rel, _ := filepath.Rel(srcSmallDir, fullPath)
		expectedSmallFiles[rel] = content
	}

	srv2, err := NewOpenFIRServer("127.0.0.1:0", outDir, sharedSecret)
	if err != nil {
		return err
	}
	srv2Err := make(chan error, 1)
	go func() { srv2Err <- srv2.Serve(true) }()

	chaos2 := NewChaosSimulator(lossRate, burstLen)
	cli2, err := NewOpenFIRClient(srv2.LocalAddr(), sharedSecret, numSockets, 80.0, 500.0, chaos2)
	if err != nil {
		srv2.Close()
		return err
	}
	if err := cli2.SendFile(srcSmallDir); err != nil {
		cli2.Close()
		srv2.Close()
		return err
	}
	cli2.Close()
	if err := <-srv2Err; err != nil {
		srv2.Close()
		return err
	}
	srv2.Close()

	dstSmallDir := filepath.Join(outDir, "small_files_dataset")
	for rel, expBytes := range expectedSmallFiles {
		gotBytes, err := os.ReadFile(filepath.Join(dstSmallDir, rel))
		if err != nil {
			return fmt.Errorf("suite 2 failure: missing extracted small file %s: %w", rel, err)
		}
		if !bytes.Equal(expBytes, gotBytes) {
			return fmt.Errorf("suite 2 failure: content mismatch in extracted small file %s", rel)
		}
	}

	totalDropped := chaos1.droppedCount + chaos2.droppedCount
	fmt.Printf("\n[SelfTest] ALL SUITES PASSED 100%%! (Total dropped packets recovered: %d)\n", totalDropped)
	return nil
}

// ============================================================================
// CLI Entrypoint
// ============================================================================

func main() {
	mode := flag.String("mode", "selftest", "Execution mode: selftest | server | client")
	listen := flag.String("listen", "0.0.0.0:9900", "Server UDP listen address")
	outDir := flag.String("out", "./openfir_downloads", "Server output directory for received files/directories")
	serverAddr := flag.String("server", "127.0.0.1:9900", "Target server UDP address for client mode")
	filePath := flag.String("file", "", "Path to input file OR directory for client mode")
	numSockets := flag.Int("sockets", 8, "Number of concurrent local UDP sockets for multi-path striping")
	initRate := flag.Float64("init-mbps", 50.0, "Initial client pacing rate in MB/s")
	maxRate := flag.Float64("max-mbps", 1000.0, "Maximum client pacing rate ceiling in MB/s")
	secretHex := flag.String("secret", "a37f92c819e4b50d", "16-char hex secret for AES-256-GCM key derivation")
	simLoss := flag.Float64("sim-loss", 0.08, "Simulated packet loss ratio (set to 0 for production)")
	simBurst := flag.Int("sim-burst", 4, "Simulated contiguous burst drop length")
	flag.Parse()

	var secret uint64 = 0xA37F92C819E4B50D
	if b, err := hex.DecodeString(*secretHex); err == nil && len(b) >= 8 {
		secret = binary.BigEndian.Uint64(b[:8])
	}

	switch *mode {
	case "selftest":
		if err := runSelfTest(*simLoss, *simBurst, *numSockets); err != nil {
			fmt.Fprintf(os.Stderr, "[Error] Self-test failed: %v\n", err)
			os.Exit(1)
		}

	case "server":
		srv, err := NewOpenFIRServer(*listen, *outDir, secret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Error] Failed to initialize server: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[Server] OpenFIR listening on %s (output dir: %s)\n", srv.LocalAddr(), *outDir)
		if err := srv.Serve(false); err != nil {
			fmt.Fprintf(os.Stderr, "[Error] Server runtime error: %v\n", err)
			os.Exit(1)
		}

	case "client":
		if *filePath == "" {
			fmt.Fprintln(os.Stderr, "[Error] -file flag (path to file or directory) is required in client mode")
			os.Exit(1)
		}
		var chaos *ChaosSimulator
		if *simLoss > 0 {
			chaos = NewChaosSimulator(*simLoss, *simBurst)
		}
		cli, err := NewOpenFIRClient(*serverAddr, secret, *numSockets, *initRate, *maxRate, chaos)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Error] Failed to initialize client: %v\n", err)
			os.Exit(1)
		}
		defer cli.Close()
		if err := cli.SendFile(*filePath); err != nil {
			fmt.Fprintf(os.Stderr, "[Error] Transfer failed: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s (expected: selftest | server | client)\n", *mode)
		os.Exit(1)
	}
}