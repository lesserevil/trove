//go:build windows

package safefs

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io/fs"
	"os"
	"syscall"
	"unsafe"
)

func openRead(r *Root, name string) (*os.File, error) { return r.R.Open(name) }

func checkPrivate(f *os.File) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !windows.EqualSid(owner, u.User.Sid) {
		return errors.New("private file must be owned by the current user")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil || acl.AceCount == 0 {
		return errors.New("private file requires an owner/System DACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("private file has an unsupported ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !windows.EqualSid(sid, u.User.Sid) && sid.String() != "S-1-5-18" {
			return errors.New("private file DACL grants another identity access")
		}
	}
	return nil
}

func forbidden(st fs.FileInfo) bool {
	if st.Mode()&os.ModeSymlink != 0 {
		return true
	}
	if d, ok := st.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	}
	return false
}

// Open the held object itself with permission-management access. An empty NT
// object name is relative to that handle, so no pathname is resolved again.
func openForProtection(f *os.File) (windows.Handle, error) {
	st, err := f.Stat()
	if err != nil {
		return windows.InvalidHandle, err
	}
	name, err := windows.NewNTUnicodeString("")
	if err != nil {
		return windows.InvalidHandle, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(f.Fd()), ObjectName: name}
	oa.Length = uint32(unsafe.Sizeof(*oa))
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if st.IsDir() {
		options |= windows.FILE_DIRECTORY_FILE
		access |= windows.FILE_LIST_DIRECTORY
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var h windows.Handle
	if err := windows.NtCreateFile(&h, access, oa, &windows.IO_STATUS_BLOCK{}, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, options, 0, 0); err != nil {
		return windows.InvalidHandle, fmt.Errorf("reopen held object for private ACL: %w", err)
	}
	// Verify identity before any permission mutation, including for renamed objects.
	var before, after windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &before); err != nil {
		windows.CloseHandle(h)
		return windows.InvalidHandle, err
	}
	if err := windows.GetFileInformationByHandle(h, &after); err != nil {
		windows.CloseHandle(h)
		return windows.InvalidHandle, err
	}
	if before.VolumeSerialNumber != after.VolumeSerialNumber || before.FileIndexHigh != after.FileIndexHigh || before.FileIndexLow != after.FileIndexLow {
		windows.CloseHandle(h)
		return windows.InvalidHandle, errors.New("private ACL handle changed object")
	}
	return h, nil
}

func protect(f *os.File) error {
	h, err := openForProtection(f)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	flags := ""
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.IsDir() {
		flags = "OICI"
	}
	// Set the current user as owner as well: elevated Windows processes can
	// otherwise create objects owned by the Administrators group.
	// A protected parent gives newly created children owner/System access from
	// creation; file protection then makes that restriction explicit and stable.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + flags + ";FA;;;" + u.User.Sid.String() + ")(A;" + flags + ";FA;;;SY)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(windows.Handle(h), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, u.User.Sid, nil, acl, nil); err != nil {
		return fmt.Errorf("protect held object DACL: %w", err)
	}
	return nil
}

// Windows rename supplies atomic namespace replacement; directory FlushFileBuffers
// is not supported. Target-specific crash durability remains a qualification gate.
func syncDir(r *Root) error { return nil }
