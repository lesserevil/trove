//go:build windows

package safefs

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsPrivateDACLAndBroadFileRejection(t *testing.T) {
	r, _ := fixture(t)
	if err := r.Write("protected", []byte("synthetic-private"), false); err != nil {
		t.Fatal(err)
	}
	if b, err := r.ReadPrivate("protected", 100); err != nil || string(b) != "synthetic-private" {
		t.Fatalf("protected read: %v", err)
	}
	f, err := r.R.OpenFile("broad", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Install an intentionally broad synthetic DACL without resolving a filename.
	h, _, e := reopenFile.Call(f.Fd(), uintptr(windows.READ_CONTROL|windows.WRITE_DAC), uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE), 0)
	if windows.Handle(h) == windows.InvalidHandle {
		t.Fatal(e)
	}
	defer windows.CloseHandle(windows.Handle(h))
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetSecurityInfo(windows.Handle(h), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ReadPrivate("broad", 100); err == nil {
		t.Fatal("Everyone DACL accepted for private input")
	}
}

// Replacing a held object's name must not redirect its permission changes.
func TestWindowsProtectionUsesHeldObject(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			r, dir := fixture(t)
			create := func() {
				t.Helper()
				var err error
				if directory {
					err = r.Mkdir("original")
				} else {
					err = r.Write("original", []byte("synthetic"), false)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			create()
			f, err := r.R.Open("original")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := r.R.Rename("original", "moved"); err != nil {
				t.Fatal(err)
			}
			create()
			replacement := filepath.Join(dir, "original")
			sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
			if err != nil {
				t.Fatal(err)
			}
			acl, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetNamedSecurityInfo(replacement, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
				t.Fatal(err)
			}
			before, err := windows.GetNamedSecurityInfo(replacement, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			if err := protect(f); err != nil {
				t.Fatal(err)
			}
			if err := checkPrivate(f); err != nil {
				t.Fatalf("held object not private: %v", err)
			}
			after, err := windows.GetNamedSecurityInfo(replacement, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			if before.String() != after.String() {
				t.Fatal("protection changed the replacement object's DACL")
			}
		})
	}
}
