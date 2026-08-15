package logic

import (
	"testing"
)

func BenchmarkLogic_ExecuteNC(b *testing.B) {
	if err := SetupTestLMKProvider(); err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	input := []byte("0007-E000")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp, err := ExecuteNC(input)
		if err != nil {
			b.Fatalf("ExecuteNC error: %v", err)
		}
		if len(resp) == 0 {
			b.Fatalf("empty response")
		}
	}
}

func BenchmarkLogic_ExecuteA0_NoZMK(b *testing.B) {
	if err := SetupTestLMKProvider(); err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	input := []byte("0000U")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp, err := ExecuteA0(input)
		if err != nil {
			b.Fatalf("ExecuteA0 error: %v", err)
		}
		if len(resp) == 0 {
			b.Fatalf("empty response")
		}
	}
}

func BenchmarkLogic_ExecuteA0_WithZMK(b *testing.B) {
	if err := SetupTestLMKProvider(); err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	input := append([]byte{'1', '0', '0', '0', 'U', 'T'}, []byte("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")...)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp, err := ExecuteA0(input)
		if err != nil {
			b.Fatalf("ExecuteA0 error: %v", err)
		}
		if len(resp) == 0 {
			b.Fatalf("empty response")
		}
	}
}

func BenchmarkLogic_ExecuteB2(b *testing.B) {
	if err := SetupTestLMKProvider(); err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	input := []byte("0004TEST")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp, err := ExecuteB2(input)
		if err != nil {
			b.Fatalf("ExecuteB2 error: %v", err)
		}
		if len(resp) == 0 {
			b.Fatalf("empty response")
		}
	}
}

func BenchmarkLogic_ExecuteCW(b *testing.B) {
	if err := SetupTestLMKProvider(); err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	input := []byte("0123456789ABCDEFFEDCBA98765432104111111111111111;2412123000")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp, err := ExecuteCW(input)
		if err != nil {
			b.Fatalf("ExecuteCW error: %v", err)
		}
		if len(resp) == 0 {
			b.Fatalf("empty response")
		}
	}
}

func BenchmarkLogic_ExecuteKQ(b *testing.B) {
	if err := SetupTestLMKProvider(); err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	input := []byte("01" + "0000000000000000" + "01" + "00" + "1122334455667788")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = ExecuteKQ(input)
	}
}
