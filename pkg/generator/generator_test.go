package generator

import (
	"errors"
	"strings"
	"testing"
)

func TestRandomCodeLength(t *testing.T) {
	wantedLength := 10

	generatedCode, err := RandomCode(wantedLength, Characters, Numbers)
	if err != nil {
		t.Errorf("unexpected error occurred while generating randomCode: %v", err)
	}
	generatedLength := len(generatedCode)

	if generatedLength != wantedLength {
		t.Fatalf("wanted length of generated randomCode is not correct, got: %d wanted: %d", generatedLength, wantedLength)
	}
}

func TestRandomCodeNoBase(t *testing.T) {
	_, err := RandomCode(10)
	if !errors.Is(err, ErrEmptyBase) {
		t.Errorf("expect RandomCode to throw '%v' but err is '%v' instead", ErrEmptyBase, err)
	}
}

func TestRandomCodeCorrectBase(t *testing.T) {
	generatedCode, err := RandomCode(20, Numbers)
	if err != nil {
		t.Errorf("unexpected error occurred while generating randomCode: %v", err)
	}

	for _, generatedCharacter := range generatedCode {
		if !strings.Contains(Numbers, string(generatedCharacter)) {
			t.Fatalf("generatedCharacter '%s' not in base '%s'", string(generatedCharacter), Numbers)
		}
	}
}

func TestCollision(t *testing.T) {
	generatedCodes := make(map[string]bool)

	for i := 0; i < 1000000; i++ {
		newCode, err := RandomCode(20, Characters, Numbers)
		if err != nil {
			t.Errorf("unexpected error occurred while generating randomCode: %v", err)
		}
		if generatedCodes[newCode] {
			t.Fatalf("collision! generated code %s was already generated", newCode)
		} else {
			generatedCodes[newCode] = true
		}
	}
}
