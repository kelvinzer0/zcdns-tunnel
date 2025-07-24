package consistenthash

import (
	"hash/crc32"
	"sort"
	"strconv"
)

// Hash function to map keys to integers.
type Hash func(data []byte) uint32

// Map holds the consistent hash ring.
type Map struct {
	hash     Hash
	replicas int            // Number of virtual nodes per real node
	keys     []int          // Sorted hashes of virtual nodes
	hashMap  map[int]string // Maps hash to real node name
}

// New creates a new Map.
// replicas is the number of virtual nodes per real node.
// fn is the hash function to use, defaults to crc32.ChecksumIEEE.
func New(replicas int, fn Hash) *Map {
	m := &Map{
		replicas: replicas,
		hash:     fn,
		hashMap:  make(map[int]string),
	}
	if m.hash == nil {
		m.hash = crc32.ChecksumIEEE
	}
	return m
}

// IsEmpty returns true if there are no items in the hash.
func (m *Map) IsEmpty() bool {
	return len(m.keys) == 0
}

// Add adds some keys to the hash.
// Each key is a real node name.
func (m *Map) Add(nodes ...string) {
	for _, node := range nodes {
		for i := 0; i < m.replicas; i++ {
			hash := int(m.hash([]byte(strconv.Itoa(i) + node)))
			m.keys = append(m.keys, hash)
			m.hashMap[hash] = node
		}
	}
	sort.Ints(m.keys)
}

// Get gets the closest item in the hash to the provided key.
func (m *Map) Get(key string) string {
	if m.IsEmpty() {
		return ""
	}

	hash := int(m.hash([]byte(key)))

	// Binary search for the closest hash.
	idx := sort.Search(len(m.keys), func(i int) bool {
		return m.keys[i] >= hash
	})

	// If we passed the last hash, wrap around to the beginning.
	if idx == len(m.keys) {
		idx = 0
	}

	return m.hashMap[m.keys[idx]]
}

// Remove removes a node from the hash ring.
func (m *Map) Remove(node string) {
	for i := 0; i < m.replicas; i++ {
		hash := int(m.hash([]byte(strconv.Itoa(i) + node)))
		delete(m.hashMap, hash)
		// Find and remove the hash from the sorted keys slice
		for j, k := range m.keys {
			if k == hash {
				m.keys = append(m.keys[:j], m.keys[j+1:]...)
				break
			}
		}
	}
	// Re-sort the keys after removal
	sort.Ints(m.keys)
}
