package kubeauth

import (
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestCachingFileReader(t *testing.T) {
	content1 := "before"
	content2 := "after"

	// Create temporary file.
	f, err := ioutil.TempFile("", "testfile")
	if err != nil {
		t.Error(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	currentTime := time.Now()

	r := newCachingFileReader(f.Name(), 1*time.Minute,
		func() time.Time {
			return currentTime
		})

	// Write initial content to file and check that we can read it.
	ioutil.WriteFile(f.Name(), []byte(content1), 0644)
	got, err := r.ReadFile()
	if err != nil {
		t.Error(err)
	}
	if got != content1 {
		t.Errorf("got '%s', expected '%s'", got, content1)
	}

	// Write new content to the file.
	ioutil.WriteFile(f.Name(), []byte(content2), 0644)

	// Advance simulated time, but not enough for cache to expire.
	currentTime = currentTime.Add(30 * time.Second)

	// Read again and check we still got the old cached content.
	got, err = r.ReadFile()
	if err != nil {
		t.Error(err)
	}
	if got != content1 {
		t.Errorf("got '%s', expected '%s'", got, content1)
	}

	// Advance simulated time for cache to expire.
	currentTime = currentTime.Add(30 * time.Second)

	// Read again and check that we got the new content.
	got, err = r.ReadFile()
	if err != nil {
		t.Error(err)
	}
	if got != content2 {
		t.Errorf("got '%s', expected '%s'", got, content2)
	}
}
