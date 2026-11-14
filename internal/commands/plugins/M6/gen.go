//go:build tinygo.wasm

//go:generate plugingen -cmd=M6 -logic=github.com/andrei-cloud/go_hsm/internal/hsm/logic -version=1.0.0 -desc "Generate a MAC" -author "anabeto93" -out=.
package main
