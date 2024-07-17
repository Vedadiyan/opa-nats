package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"booqall.com/middlewares/opa/internal"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	conn, err := nats.Connect(os.Getenv("default_nats"))
	if err != nil {
		log.Fatalln(err)
	}
	js, err := conn.JetStream()
	if err != nil {
		log.Fatalln(err)
	}
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{
		Bucket:  "OPA_STORE",
		Storage: nats.FileStorage,
	})
	if err != nil && err != jetstream.ErrBucketExists {
		log.Fatalln(err)
	}
	err = internal.Initialize(kv)
	if err != nil {
		log.Fatalln(err)
	}
	err = internal.Watch(kv)
	if err != nil {
		log.Fatalln(err)
	}
	subs, err := conn.QueueSubscribe("$OPA", "balanced", Handler)
	if err != nil {
		log.Fatalln(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	err = subs.Drain()
	if err != nil {
		log.Fatalln(err)
	}
	for subs.IsValid() {
		<-time.After(time.Second)
	}
}

func Handler(msg *nats.Msg) {
	input := make(map[string]any)
	err := json.Unmarshal(msg.Data, &input)
	if err != nil {
		Error(msg, 500, err)
		return
	}
	output := make(map[string]any)
	for _, policy := range msg.Header.Values("X-Policies") {
		data, err := internal.Eval(context.TODO(), policy, input)
		if err != nil {
			output[policy] = err
			continue
		}
		output[policy] = data
	}
	json, err := json.Marshal(output)
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
}

func Error(msg *nats.Msg, statusCode int, err error) {
	_ = msg.RespondMsg(&nats.Msg{
		Header: nats.Header{
			"X-Status": []string{fmt.Sprintf("%d", statusCode)},
			"X-Error":  []string{err.Error()},
		},
	})
}
