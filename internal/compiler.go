package internal

import (
	"context"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/types"
)

func init() {
	rego.RegisterBuiltin1(&rego.Function{
		Name: "jwt.parse",
		Decl: types.NewFunction([]types.Type{types.String{}}, types.NewObject(nil, types.NewDynamicProperty(types.S, types.S))),
	}, JWTDecode)
}

func JWTDecode(bctx rego.BuiltinContext, op1 *ast.Term) (*ast.Term, error) {
	jwtKey := os.Getenv("JWT_KEY")
	inst, err := jwt.Parse(op1.String(), func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	val, err := ast.InterfaceToValue(map[string]any{
		"Headers": inst.Header,
		"Claims":  inst.Claims,
		"Valid":   inst.Valid,
	})
	if err != nil {
		return nil, err
	}
	return &ast.Term{Value: val}, nil
}

func Prepare(policyName string, definition []byte) (*Module, error) {
	opts := ast.CompileOpts{}
	opts.ParserOptions.ProcessAnnotation = true
	compiler, err := ast.CompileModulesWithOpt(map[string]string{
		policyName: string(definition),
	}, opts)
	if err != nil {
		return nil, err
	}
	module := (*Module)(compiler.Modules[policyName])
	return module, nil
}

func (module *Module) Eval(ctx context.Context, input Input, store storage.Store) (map[string]map[string]any, error) {
	mod := (*ast.Module)(module)
	path := module.Package.Path.String()
	rego := rego.New(
		rego.ParsedModule(mod),
		rego.Query(path),
		rego.Input(input),
		rego.Store(store),
	)
	rs, err := rego.Eval(ctx)
	if err != nil {
		return nil, err
	}
	if len(rs) != 1 {
		return nil, fmt.Errorf("no result")
	}

	res, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected map[string]any but found %T", rs[0].Expressions[0])
	}

	output := make(map[string]map[string]any)
	for key, value := range res {
		rule := module.GetRule(key)
		if rule == nil {
			return nil, fmt.Errorf("could not find rule `%s`", key)
		}
		output[key] = map[string]any{
			"result":   value,
			"metadata": rule.Annotations,
		}
	}
	return output, nil
}

func (module *Module) GetRule(ruleName string) *ast.Rule {
	for _, i := range module.Rules {
		if i.Head.Name.String() == ruleName {
			return i
		}
	}
	return nil
}
