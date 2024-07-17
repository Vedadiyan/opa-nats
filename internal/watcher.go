package internal

import (
	"github.com/nats-io/nats.go"
)

var (
	_reInitialize func() error
)

func Watch(kv nats.KeyValue) error {
	watcher, err := kv.WatchAll()
	if err != nil {
		return err
	}
	go func() {
		for update := range watcher.Updates() {
			if update == nil {
				continue
			}
			module, err := Prepare(update.Key(), update.Value())
			if err != nil {
				continue
			}
			_mut.Lock()
			_modules[update.Key()] = module
			_mut.Unlock()
		}
	}()
	return nil
}

func Initialize(kv nats.KeyValue) error {
	_reInitialize = func() error {
		keys, err := kv.Keys()
		if err != nil && err != nats.ErrNoKeysFound {
			return err
		}
		for _, key := range keys {
			value, err := kv.Get(key)
			if err != nil {
				return err
			}
			module, err := Prepare(key, value.Value())
			if err != nil {
				return err
			}
			_mut.Lock()
			_modules[key] = module
			_mut.Unlock()
		}
		return nil
	}
	return _reInitialize()
}
