package hmqv

import (
	"testing"
)

//func TestAgree(t *testing.T) {
//	var tests = []struct {
//		a, b int
//		want int
//	}{
//		{0, 1, 0},
//		{1, 0, 0},
//		{2, -2, -2},
//		{0, -1, -1},
//		{-1, 0, -1},
//	}
//	for _, tt := range tests {
//
//		testname := fmt.Sprintf("%d,%d", tt.a, tt.b)
//		t.Run(testname, func(t *testing.T) {
//			ans := IntMin(tt.a, tt.b)
//			if ans != tt.want {
//				t.Errorf("got %d, want %d", ans, tt.want)
//			}
//		})
//	}
//
//}

func BenchmarkHMQV(b *testing.B) {
	// Setup
	sprivA_Int, spubA_x_Int, spubA_y_Int := GenerateKeys()
	staticKeysAlice := StaticKeys{sprivA_Int, spubA_x_Int, spubA_y_Int}
	sprivB_Int, spubB_x_Int, spubB_y_Int := GenerateKeys()
	staticKeysBob := StaticKeys{sprivB_Int, spubB_x_Int, spubB_y_Int}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Epheremal keys
		eprivA_Int, epubA_x_Int, epubA_y_Int := GenerateKeys()
		ephemeralKeysAlice := EphemeralKeys{eprivA_Int, epubA_x_Int, epubA_y_Int}
		eprivB_Int, epubB_x_Int, epubB_y_Int := GenerateKeys()
		ephemeralKeysBob := EphemeralKeys{eprivB_Int, epubB_x_Int, epubB_y_Int}
		_ = Agree(&staticKeysAlice, &ephemeralKeysAlice, &staticKeysBob, &ephemeralKeysBob, true)
	}
}
