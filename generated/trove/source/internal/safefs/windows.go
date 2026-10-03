//go:build windows

package safefs

import (
	"errors"
	"golang.org/x/sys/windows"
	"io/fs"
	"os"
	"syscall"
	"unsafe"
)

var reopenFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")

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

func protect(f *os.File) error {
	// os.Open does not request WRITE_DAC. Reopen the held object rather than
	// resolving its name again, so a path swap cannot redirect ACL changes.
	h, _, e := reopenFile.Call(f.Fd(), uintptr(windows.READ_CONTROL|windows.WRITE_DAC),
		uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE),
		uintptr(windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT))
	if windows.Handle(h) == windows.InvalidHandle {
		if e != nil {
			return e
		}
		return errors.New("ReOpenFile failed")
	}
	defer windows.CloseHandle(windows.Handle(h))
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
	return windows.SetSecurityInfo(windows.Handle(h), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// Windows rename supplies atomic namespace replacement; directory FlushFileBuffers
// is not supported. Target-specific crash durability remains a qualification gate.
func syncDir(r *Root) error { return nil }
