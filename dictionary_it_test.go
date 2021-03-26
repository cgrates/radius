// +build integration

package radigo

import (
	"fmt"
	"os"
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

// func TestDictionaryParseFromFolder2(t *testing.T) {
// 	dict := &Dictionary{}
// 	dirPath := "/tmp/TestDictionaryParseFromFolderEmptyFile"

// 	err := os.Mkdir(dirPath, 0755)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer os.RemoveAll(dirPath)

// 	err = ioutil.WriteFile(dirPath+"/dictionary.", []byte("testString"), 0644)
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	err = dict.ParseFromFolder(dirPath)

// 	if err != nil {
// 		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
// 	}
// }
