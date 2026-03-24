package common

import "sync"

type ConcurrentMap[K comparable, V any] struct {
	m map[K]V
	k sync.RWMutex
}

func NewConcurrentMap[K comparable, V any]() *ConcurrentMap[K, V] {
	return &ConcurrentMap[K, V]{m: make(map[K]V)}
}

func (cm *ConcurrentMap[K, V]) Store(key K, val V) {
	cm.k.Lock()
	defer cm.k.Unlock()
	cm.m[key] = val
}

func (cm *ConcurrentMap[K, V]) Load(key K) (V, bool) {
	cm.k.RLock()
	defer cm.k.RUnlock()
	val, ok := cm.m[key]
	return val, ok
}

func (cm *ConcurrentMap[K, V]) Delete(key K) {
	cm.k.Lock()
	defer cm.k.Unlock()
	delete(cm.m, key)
}

func (cm *ConcurrentMap[K, V]) Range(f func(K, V) bool) {
	cm.k.RLock()
	defer cm.k.RUnlock()
	for k, v := range cm.m {
		if !f(k, v) {
			return
		}
	}
}
