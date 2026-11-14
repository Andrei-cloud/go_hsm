//go:build tinygo.wasm

//go:generate plugingen -cmd=A8 -logic=github.com/andrei-cloud/go_hsm/internal/hsm/logic -version=1.0.0 -desc "Export a key under ZMK" -author "anabeto93" -out=.
package main
