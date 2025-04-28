module github.com/andrei-cloud/go_hsm

go 1.24.2

require (
	github.com/andrei-cloud/anet v0.0.0-20250427111049-114167d09809
	github.com/rs/zerolog v1.34.0
	github.com/tetratelabs/wazero v1.9.0
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
)

replace github.com/andrei-cloud/anet => ../anet

replace github.com/andrei-cloud/go_hsm => .
