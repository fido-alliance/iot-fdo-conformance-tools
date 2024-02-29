package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: delete path")
		fmt.Println("Usage: copy path1 path2")

		return
	}

	cmd := os.Args[1]
	path1 := os.Args[2]

	switch cmd {
	case "copy":
		if len(os.Args) < 3 {
			fmt.Println("Usage: copy path1 path2")
			return
		}

		path2 := os.Args[3]
		if _, err := os.Stat(path1); err == nil {
			err := copyFileOrFolder(path1, path2)
			if err != nil {
				fmt.Println("Error copying file or folder:", err)
				return
			}
			fmt.Println("File or folder copied successfully")
		} else {
			fmt.Println("File or folder does not exist")
		}
	case "delete":
		if _, err := os.Stat(path1); err == nil {
			err := os.RemoveAll(path1)
			if err != nil {
				fmt.Println("Error deleting file or folder:", err)
				return
			}
			fmt.Println("File or folder deleted successfully")
		} else {
			fmt.Println("File or folder does not exist")
		}
	default:
		fmt.Println("Invalid command")
	}
}

func copyFileOrFolder(src, dest string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if srcInfo.IsDir() {
		return copyFolder(src, dest)
	} else {
		return copyFile(src, dest)
	}
}

func copyFile(src, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return err
	}

	return nil
}

func copyFolder(src, dest string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dest, srcInfo.Mode())
	if err != nil {
		return err
	}

	dir, err := os.Open(src)
	if err != nil {
		return err
	}
	defer dir.Close()

	files, err := dir.Readdir(-1)
	if err != nil {
		return err
	}

	for _, file := range files {
		srcFile := filepath.Join(src, file.Name())
		destFile := filepath.Join(dest, file.Name())

		if file.IsDir() {
			err = copyFolder(srcFile, destFile)
			if err != nil {
				return err
			}
		} else {
			err = copyFile(srcFile, destFile)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
