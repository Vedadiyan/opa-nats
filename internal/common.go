package internal

import (
	"context"
	"sync"

	"github.com/open-policy-agent/opa/ast"
)

type (
	Module ast.Module
	Input  map[string]any
)

var (
	_modules map[string]*Module
	_mut     sync.RWMutex
)

func init() {
	_modules = make(map[string]*Module)
}

func Eval(ctx context.Context, policyName string, input Input) (map[string]map[string]any, error) {
	var module *Module
	for i := 0; i < 2; i++ {
		_mut.RLock()
		mod, ok := _modules[policyName]
		_mut.RUnlock()
		if !ok {
			err := _reInitialize()
			if err != nil {
				return nil, err
			}
			continue
		}
		module = mod
	}
	return module.Eval(ctx, input, nil)
}
