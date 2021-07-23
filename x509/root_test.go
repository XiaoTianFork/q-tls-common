package x509

import "testing"

func TestLoadSystem(t *testing.T) {

	roots, err := loadSystemRoots()
	if err != nil {
		t.Error(err)
	}
	if roots == nil {
		t.Error("system root is nil")
	}
}
