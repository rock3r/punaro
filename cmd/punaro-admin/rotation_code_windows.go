package main

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

func readProtectedRotationCodeFile(path string) ([]byte, error) {
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("rotation code file is not protected")
	}
	handle, err := windows.CreateFile(pathUTF16, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0) // #nosec G304 -- explicit host-local path opened as the reparse point itself.
	if err != nil {
		return nil, errors.New("rotation code file is not protected")
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil || handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("rotation code file is not protected")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("rotation code file is not protected")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("rotation code file is not protected")
	}
	return io.ReadAll(io.LimitReader(file, 44))
}
