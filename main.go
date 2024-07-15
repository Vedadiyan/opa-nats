package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/types"
)

type (
	PolicyStore struct {
		conn *nats.Conn
		kv   nats.KeyValue
		subs *nats.Subscription
		once sync.Once
	}
)

func init() {
	jwtKey := os.Getenv("JWT_KEY")
	rego.RegisterBuiltin1(&rego.Function{
		Name: "jwt.parse",
		Decl: types.NewFunction([]types.Type{types.String{}}, types.NewObject(nil, types.NewDynamicProperty(types.S, types.S))),
	}, func(bctx rego.BuiltinContext, op1 *ast.Term) (*ast.Term, error) {
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
	})
}

func main() {
	conn, err := nats.Connect(os.Getenv("default_nats"))
	if err != nil {
		log.Fatalln(err)
	}
	policyStore, err := New(conn)
	if err != nil {
		log.Fatalln(err)
	}
	err = policyStore.Listen()
	if err != nil {
		log.Fatalln(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	err = policyStore.subs.Drain()
	if err != nil {
		log.Fatalln(err)
	}
	for policyStore.subs.IsValid() {
		<-time.After(time.Second)
	}
}

func JWTDecode(ctx context.Context, bctx rego.BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	name, ok := operands[0].Value.(ast.String)
	if !ok {
		return fmt.Errorf("expected ast.String but found %t", operands[0].Value)
	}
	greeting := "Hello, " + string(name)
	result := ast.StringTerm(greeting)
	return iter(result)
}

func New(conn *nats.Conn) (*PolicyStore, error) {
	js, err := conn.JetStream()
	if err != nil {
		return nil, err
	}
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{
		Bucket:  "OPA_STORE",
		Storage: nats.FileStorage,
	})
	if err != nil && err != jetstream.ErrBucketExists {
		return nil, err
	}
	policyStore := new(PolicyStore)
	policyStore.kv = kv
	policyStore.conn = conn
	return policyStore, nil
}

func (policyStore *PolicyStore) Listen() error {
	var err error
	policyStore.once.Do(func() {
		store := inmem.NewFromObject(map[string]any{})
		subs, err := policyStore.conn.QueueSubscribe("$OPA.*", "balanced", func(msg *nats.Msg) {
			path := strings.TrimPrefix(msg.Subject, "$OPA.*")
			sha256 := sha256.New()
			_, err := sha256.Write([]byte(path))
			if err != nil {
				Error(msg, 500, err)
				return
			}
			hash := sha256.Sum(nil)
			hexHash := hex.EncodeToString(hash)
			policy, err := policyStore.kv.Get(hexHash)
			if err != nil {
				Error(msg, 404, err)
				return
			}
			input := map[string]any{
				"headers": msg.Header,
				"path":    path,
				"data":    string(msg.Data),
			}
			r := rego.New(
				rego.Store(store),
				rego.Module(fmt.Sprintf("%s.rego", hexHash), string(policy.Value())),
				rego.Input(input),
			)
			rs, err := r.Eval(context.TODO())
			if err != nil {
				Error(msg, 500, err)
				return
			}
			json, err := json.Marshal(rs)
			if err != nil {
				Error(msg, 500, err)
				return
			}
			_ = msg.RespondMsg(&nats.Msg{
				Header: nats.Header{
					"X-Status": []string{"200"},
				},
				Data: json,
			})

		})
		if err != nil {
			return
		}
		policyStore.subs = subs
	})
	return err
}

func Error(msg *nats.Msg, statusCode int, err error) {
	_ = msg.RespondMsg(&nats.Msg{
		Header: nats.Header{
			"X-Status": []string{fmt.Sprintf("%d", statusCode)},
			"X-Error":  []string{err.Error()},
		},
	})
}
