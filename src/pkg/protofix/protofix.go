package main

import(
	"os"
	"fmt"

	protofix "github.com/pachyderm/pachyderm/src/pkg/protofix/lib"
)

func usage() {
	fmt.Println("usage: protofix fix <rootdirectory>")
	fmt.Println("usage: protofix revert <rootdirectory>")
}

func main() {

	if len(os.Args) < 3 {
		fmt.Println("Missing root directory")
		usage()
		os.Exit(1)
	}

	if os.Args[1] == "fix" {
		protofix.FixAllPBGOFilesInDirectory(os.Args[2])
	}
	if os.Args[1] == "revert" {
		protofix.RevertAllPBGOFilesInDirectory(os.Args[2])
	}

}
