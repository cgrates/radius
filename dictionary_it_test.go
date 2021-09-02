//go:build integration
// +build integration

package radigo

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDictionaryParseFromFolderInvalidDir(t *testing.T) {
	dict := &Dictionary{}
	dirPath := "/tmp/TestDictionaryParseFromFolderInvalidDir"

	err := os.Mkdir(dirPath, 0755)
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dirPath)

	f, err := os.Create(dirPath + "/emptyfile.txt")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()

	experr := fmt.Sprintf("path: %s not a directory.", dirPath+"/emptyfile.txt")
	err = dict.ParseFromFolder(dirPath + "/emptyfile.txt")

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestDictionaryParseFromFolderEmptyFile(t *testing.T) {
	dict := &Dictionary{}
	dirPath := "/tmp/TestDictionaryParseFromFolderEmptyFile"

	err := os.Mkdir(dirPath, 0755)
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dirPath)

	f, err := os.Create(dirPath + "/emptyfile.txt")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()

	err = dict.ParseFromFolder(dirPath)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}
}

func TestDictionaryParseFromFolderBadPattern(t *testing.T) {
	dict := &Dictionary{}
	dirPath := "[]"

	err := os.Mkdir(dirPath, 0755)
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dirPath)

	experr := filepath.ErrBadPattern
	err = dict.ParseFromFolder(dirPath)

	if err == nil || err != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestDictionaryParseFromFolderNoPermission(t *testing.T) {
	dict := &Dictionary{}
	dirPath := "/tmp/TestDictionaryParseFromFolderNoPermission"

	err := os.Mkdir(dirPath, 0755)
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dirPath)

	err = os.WriteFile(dirPath+"/dictionary.txt", []byte("testString"), 0311)
	if err != nil {
		t.Error(err)
	}
	e := fmt.Errorf("permission denied")
	experr := &os.PathError{Op: "open", Path: dirPath + "/dictionary.txt", Err: e}
	err = dict.ParseFromFolder(dirPath)

	if err == nil || err.Error() != experr.Error() {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

// func TestDictionaryParseFromFolderFailParse(t *testing.T) {
// 	dict := &Dictionary{}
// 	dirPath := "/tmp/TestDictionaryParseFromFolderFailParse"

// 	err := os.Mkdir(dirPath, 0755)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer os.RemoveAll(dirPath)

// 	f, err := os.Create(dirPath + "/dictionary.txt")
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	f.Write([]byte("123\n"))
// 	for i := 0; i < 70000; i++ {
// 		f.Write([]byte("123"))
// 	}
// 	f.Write([]byte("123\n"))
// 	f.Close()
// 	experr := ""
// 	err = dict.ParseFromFolder(dirPath)

// 	if err == nil || err.Error() != experr {
// 		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
// 	}
// }
