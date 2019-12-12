package kubeauth

import (
	"testing"

	"github.com/hashicorp/vault/sdk/helper/strutil"
)

func TestStrListContainsGlob(t *testing.T) {
	if !strutil.StrListContainsGlob([]string{"f*", "foo"}, "foo") {
		t.Fatal("should contain glob")
	}
	if !strutil.StrListContainsGlob([]string{"foo", "f*"}, "foo") {
		t.Fatal("should contain glob")
	}
}
