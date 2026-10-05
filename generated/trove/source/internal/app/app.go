// Package app owns the CLI and transactions; the OpenPGP adapter is supplied by main.
package app

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"trove/internal/format"
	"trove/internal/safefs"
)

const MaxKey = 1 << 20

type Crypto interface {
	Public([]byte) ([]byte, string, error)
	Generate(string, string, []byte) ([]byte, []byte, string, error)
	Import([]byte, []byte) ([]byte, []byte, string, error)
	Wrap([]byte, []byte) ([]byte, error)
	Unwrap([]byte, []byte, []byte) ([]byte, error)
}

type App struct {
	Crypto   Crypto
	In       io.Reader
	Out, Err io.Writer
	Prompt   func() ([]byte, error)
	Version  string
}

type options struct {
	store, identity, user, name, file, key, recipient, email, dir, passfile string
	legacy                                                                  bool
}

var commands = map[string]bool{
	"init": true, "check-deps": true, "generate-key": true, "new-user": true,
	"add-user": true, "import-key": true, "export-key": true, "import-secret-key": true,
	"create-secret": true, "read-secret": true, "update-secret": true,
	"grant-access": true, "revoke-access": true, "list-secrets": true,
	"list-users": true, "delete-secret": true, "migrate": true,
}

func (a *App) Run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := fmt.Fprintln(a.Out, `Trove — offline shared secrets, embedded OpenPGP
Usage: trove COMMAND [flags]
Commands: init, check-deps, generate-key, new-user, add-user, import-key,
  export-key, import-secret-key, create-secret, read-secret, update-secret,
  grant-access, revoke-access, list-secrets, list-users, delete-secret, migrate
Common: --store DIR --identity-dir DIR --user ID --passphrase-file FILE
Commands use --name NAME, --file FILE (or -), --key FILE, --recipient ID,
  --email EMAIL, --dir EXPORT_DIR, --accept-unauthenticated-legacy
Use 'trove COMMAND --help' for flags. No external runtime or crypto tools required.`)
		return err
	}
	if args[0] == "version" || args[0] == "--version" {
		_, e := fmt.Fprintf(a.Out, "trove %s %s/%s\n", a.Version, runtime.GOOS, runtime.GOARCH)
		return e
	}
	cmd := args[0]
	if !commands[cmd] {
		return fmt.Errorf("unknown command %q", cmd)
	}
	o := options{}
	var err error
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	f.SetOutput(a.Err)
	f.StringVar(&o.store, "store", ".", "store directory")
	f.StringVar(&o.identity, "identity-dir", "", "external protected identity directory (default: user config/trove/identities)")
	f.StringVar(&o.user, "user", "", "acting identity (defaults to PM_USER or login name)")
	f.StringVar(&o.name, "name", "", "secret or identity name")
	f.StringVar(&o.file, "file", "-", "content source; - reads stdin")
	f.StringVar(&o.key, "key", "", "public/private key input file; - reads stdin")
	f.StringVar(&o.recipient, "recipient", "", "grant/revoke recipient")
	f.StringVar(&o.email, "email", "", "identity email")
	f.StringVar(&o.dir, "dir", "", "external existing export directory")
	f.StringVar(&o.passfile, "passphrase-file", "", "private file containing a nonempty passphrase")
	f.BoolVar(&o.legacy, "accept-unauthenticated-legacy", false, "acknowledge CBC cannot prove authenticity")
	if err = f.Parse(args[1:]); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if cmd == "check-deps" {
		_, err := fmt.Fprintln(a.Out, "Embedded OpenPGP and AES-GCM; no external programs required.")
		return err
	}
	if o.identity == "" {
		config, err := os.UserConfigDir()
		if err != nil {
			return fmt.Errorf("set --identity-dir or configure the user config directory: %w", err)
		}
		o.identity = filepath.Join(config, "trove", "identities")
	}
	identityCommand := cmd == "generate-key" || cmd == "new-user" || cmd == "add-user" || cmd == "import-key" || cmd == "import-secret-key" || cmd == "export-key"
	if cmd != "init" && cmd != "list-users" && cmd != "list-secrets" {
		if err := safefs.Name(o.name, !identityCommand); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}
	if o.user != "" {
		if err := safefs.Name(o.user, false); err != nil {
			return err
		}
	}
	if cmd == "grant-access" || cmd == "revoke-access" {
		if err := safefs.Name(o.recipient, false); err != nil {
			return fmt.Errorf("recipient: %w", err)
		}
	}
	if err := external(o.identity, o.store); err != nil {
		return fmt.Errorf("identity directory: %w", err)
	}
	if cmd == "export-key" {
		if o.dir == "" {
			return errors.New("export requires --dir outside the store")
		}
		if err := external(o.dir, o.store); err != nil {
			return fmt.Errorf("export directory: %w", err)
		}
	}
	if cmd == "migrate" && !o.legacy {
		return errors.New("migration requires --accept-unauthenticated-legacy and an encrypted store backup")
	}
	store, err := safefs.Open(o.store, cmd == "init")
	if err != nil {
		return err
	}
	defer store.Close()
	if cmd == "init" {
		if err := store.Private(); err != nil {
			return err
		}
		unlock, err := store.Lock()
		if err != nil {
			return err
		}
		defer unlock()
		if err := store.MkdirAll("users"); err != nil {
			return err
		}
		return store.MkdirAll("secrets")
	}
	if err = store.Check("users"); err != nil {
		return fmt.Errorf("run init first: %w", err)
	}
	if err = store.Check("secrets"); err != nil {
		return fmt.Errorf("run init first: %w", err)
	}
	if cmd == "list-users" {
		return a.listUsers(store)
	}
	if cmd == "list-secrets" {
		return a.listSecrets(store, "secrets")
	}
	if o.user == "" {
		if identityCommand {
			o.user = o.name
		} else {
			o.user = currentUser(store)
		}
	}
	if err = safefs.Name(o.user, false); err != nil {
		return fmt.Errorf("acting user: %w", err)
	}
	if cmd == "read-secret" {
		return a.read(store, o)
	}
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	switch cmd {
	case "add-user", "import-key":
		if o.key == "" {
			return errors.New("explicit --key export file required; GPG keyrings are not read")
		}
		data, err := a.input(o.key, MaxKey, false)
		if err != nil {
			return err
		}
		pub, fingerprint, err := a.Crypto.Public(data)
		if err != nil {
			return err
		}
		if err = store.Write("users/"+o.name+".pub", pub, false); err != nil {
			return err
		}
		_, err = fmt.Fprintf(a.Err, "Registered %s: %s\n", o.name, fingerprint)
		return err
	case "generate-key", "new-user", "import-secret-key":
		return a.identity(store, o, cmd)
	case "export-key":
		return a.export(store, o)
	case "create-secret":
		return a.create(store, o)
	case "update-secret", "grant-access", "revoke-access", "delete-secret", "migrate":
		return a.change(store, o, cmd)
	}
	return errors.New("unimplemented command")
}

func inside(child, parent string) bool {
	// Fail closed on case aliases on the supported case-insensitive platforms.
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		child = strings.ToLower(child)
		parent = strings.ToLower(parent)
	}
	r, err := filepath.Rel(parent, child)
	return err == nil && (r == "." || r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)))
}

func insideExisting(child, parent string) bool {
	if inside(child, parent) {
		return true
	}
	root, err := os.Stat(parent)
	if err != nil {
		return false
	}
	// Identity directories may not exist yet. Comparing existing ancestors also
	// catches Windows short-name aliases and alternate spellings of the same root.
	for p := child; ; p = filepath.Dir(p) {
		if st, err := os.Stat(p); err == nil && os.SameFile(st, root) {
			return true
		}
		if filepath.Dir(p) == p {
			return false
		}
	}
}

func external(dir, store string) error {
	d, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	s, err := filepath.Abs(store)
	if err != nil {
		return err
	}
	if insideExisting(d, s) {
		return errors.New("must be outside the store")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	for p := cwd; ; p = filepath.Dir(p) {
		if _, e := os.Stat(filepath.Join(p, "literate.project.json")); e == nil && insideExisting(d, p) {
			return errors.New("must be outside the source repository")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

func currentUser(s *safefs.Root) string {
	if p := os.Getenv("PM_USER"); p != "" {
		return p
	}
	u := os.Getenv("USER")
	if u == "" {
		u = os.Getenv("USERNAME")
	}
	h, _ := os.Hostname()
	h = strings.Split(h, ".")[0]
	if safefs.Name(u+"@"+h, false) == nil && s.Check("users/"+u+"@"+h+".pub") == nil {
		return u + "@" + h
	}
	return u
}

func (a *App) input(filename string, limit int64, private bool) ([]byte, error) {
	if filename == "-" {
		if private {
			return nil, errors.New("private passphrase input must use a file or terminal")
		}
		return safefs.ReadBounded(a.In, limit)
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	r, err := safefs.Open(filepath.Dir(abs), false)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if private {
		return r.ReadPrivate(filepath.Base(abs), limit)
	}
	return r.Read(filepath.Base(abs), limit)
}

func (a *App) pass(o options) ([]byte, error) {
	var b []byte
	var err error
	if o.passfile != "" {
		b, err = a.input(o.passfile, 4096, true)
	} else if a.Prompt != nil {
		b, err = a.Prompt()
	} else {
		err = errors.New("supply --passphrase-file or use an interactive terminal")
	}
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if len(b) == 0 || len(b) > 4096 {
		clear(b)
		return nil, errors.New("nonempty passphrase of at most 4096 bytes required")
	}
	return b, nil
}

func (a *App) identity(store *safefs.Root, o options, cmd string) error {
	pass, err := a.pass(o)
	if err != nil {
		return err
	}
	defer clear(pass)
	var pub, priv []byte
	var fp string
	if cmd == "import-secret-key" {
		if o.key == "" {
			return errors.New("--key required")
		}
		data, e := a.input(o.key, MaxKey, false)
		if e != nil {
			return e
		}
		defer clear(data)
		pub, priv, fp, err = a.Crypto.Import(data, pass)
	} else {
		pub, priv, fp, err = a.Crypto.Generate(o.name, o.email, pass)
	}
	if err != nil {
		return err
	}
	defer clear(priv)
	id, err := safefs.Open(o.identity, true)
	if err != nil {
		return err
	}
	defer id.Close()
	if err = id.Private(); err != nil {
		return err
	}
	unlock, err := id.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	// Never replace an identity; this prevents accidental recipient/key divergence.
	if err = id.Write(o.name+".secret.key", priv, false); err != nil {
		return err
	}
	if cmd == "new-user" {
		if err = store.Write("users/"+o.name+".pub", pub, false); err != nil {
			_ = id.Remove(o.name + ".secret.key")
			return err
		}
	}
	if cmd == "generate-key" {
		if err = id.Write(o.name+".pub", pub, false); err != nil {
			_ = id.Remove(o.name + ".secret.key")
			return err
		}
	}
	_, err = fmt.Fprintf(a.Err, "Protected identity %s: %s\n", o.name, fp)
	return err
}

func (a *App) export(store *safefs.Root, o options) error {
	id, err := safefs.Open(o.identity, false)
	if err != nil {
		return err
	}
	defer id.Close()
	priv, err := id.ReadPrivate(o.name+".secret.key", MaxKey)
	if err != nil {
		return err
	}
	defer clear(priv)
	pass, err := a.pass(o)
	if err != nil {
		return err
	}
	defer clear(pass)
	pub, protected, _, err := a.Crypto.Import(priv, pass)
	if err != nil {
		return err
	}
	defer clear(protected)
	dest, err := safefs.Open(o.dir, false)
	if err != nil {
		return err
	}
	defer dest.Close()
	if err = dest.Private(); err != nil {
		return err
	}
	unlock, err := dest.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err = dest.Write(o.name+".secret.key", protected, false); err != nil {
		return err
	}
	if err = dest.Write(o.name+".pub", pub, false); err != nil {
		_ = dest.Remove(o.name + ".secret.key")
		return err
	}
	return nil
}

func (a *App) rootKey(store *safefs.Root, o options) ([]byte, error) {
	env, err := store.Read("secrets/"+o.name+"/"+o.user+".key.enc", MaxKey)
	if err != nil {
		return nil, fmt.Errorf("recipient access: %w", err)
	}
	id, err := safefs.Open(o.identity, false)
	if err != nil {
		return nil, err
	}
	defer id.Close()
	priv, err := id.ReadPrivate(o.user+".secret.key", MaxKey)
	if err != nil {
		return nil, err
	}
	defer clear(priv)
	pass, err := a.pass(o)
	if err != nil {
		return nil, err
	}
	defer clear(pass)
	data, err := a.Crypto.Unwrap(priv, pass, env)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return format.ParseRootKey(data)
}

func (a *App) read(store *safefs.Root, o options) error {
	key, err := a.rootKey(store, o)
	if err != nil {
		return err
	}
	defer clear(key)
	data, err := store.Read("secrets/"+o.name+"/secret.enc", format.MaxContent+128)
	if err != nil {
		return err
	}
	plain, err := format.Decrypt(key, o.name, data)
	if err != nil {
		return err
	}
	defer clear(plain)
	_, err = a.Out.Write(plain)
	return err
}

func (a *App) create(store *safefs.Root, o options) error {
	if err := store.Check("secrets/" + o.name); err == nil {
		return fs.ErrExist
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	pub, err := store.Read("users/"+o.user+".pub", MaxKey)
	if err != nil {
		return err
	}
	plain, err := a.input(o.file, format.MaxContent, false)
	if err != nil {
		return err
	}
	defer clear(plain)
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return err
	}
	defer clear(key)
	enc, err := format.Encrypt(key, o.name, plain)
	if err != nil {
		return err
	}
	rootText := []byte(hex.EncodeToString(key) + "\n")
	defer clear(rootText)
	env, err := a.Crypto.Wrap(pub, rootText)
	if err != nil {
		return err
	}
	parent := path.Dir("secrets/" + o.name)
	for p := parent; p != "secrets" && p != "."; p = path.Dir(p) {
		if err := store.Check(p + "/secret.enc"); err == nil {
			return errors.New("cannot nest a secret beneath another secret")
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err = store.MkdirAll(parent); err != nil {
		return err
	}
	var n [16]byte
	if _, err = rand.Read(n[:]); err != nil {
		return err
	}
	stage := path.Join(parent, ".create-"+hex.EncodeToString(n[:]))
	if err = store.Mkdir(stage); err != nil {
		return err
	}
	defer store.RemoveTree(stage)
	if err = store.Write(stage+"/secret.enc", enc, false); err != nil {
		return err
	}
	if err = store.Write(stage+"/"+o.user+".key.enc", env, false); err != nil {
		return err
	}
	d, err := store.Sub(parent)
	if err != nil {
		return err
	}
	defer d.Close()
	if err = d.Check(path.Base(o.name)); err == nil {
		return fs.ErrExist
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return d.R.Rename(path.Base(stage), path.Base(o.name))
}

func (a *App) change(store *safefs.Root, o options, cmd string) error {
	key, err := a.rootKey(store, o)
	if err != nil {
		return err
	}
	defer clear(key)
	base := "secrets/" + o.name
	data, err := store.Read(base+"/secret.enc", format.MaxContent+128)
	if err != nil {
		return err
	}
	var plain []byte
	if cmd == "migrate" && !format.IsV2(data) {
		plain, err = format.DecryptLegacy(key, data)
	} else {
		plain, err = format.Decrypt(key, o.name, data)
	}
	if err != nil {
		return err
	}
	defer clear(plain)
	switch cmd {
	case "delete-secret":
		entries, err := store.List(base)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				return errors.New("secret contains a directory; refusing recursive deletion of other secrets")
			}
		}
		return store.RemoveTree(base)
	case "revoke-access":
		if o.recipient == o.user {
			return errors.New("cannot revoke acting identity; preserve recoverability")
		}
		if err := store.Remove(base + "/" + o.recipient + ".key.enc"); err != nil {
			return err
		}
		_, err := fmt.Fprintln(a.Err, "Envelope removed; previously recovered keys and history remain accessible.")
		return err
	case "grant-access":
		pub, err := store.Read("users/"+o.recipient+".pub", MaxKey)
		if err != nil {
			return err
		}
		text := []byte(hex.EncodeToString(key) + "\n")
		defer clear(text)
		env, err := a.Crypto.Wrap(pub, text)
		if err != nil {
			return err
		}
		return store.Write(base+"/"+o.recipient+".key.enc", env, false)
	case "update-secret":
		updated, err := a.input(o.file, format.MaxContent, false)
		if err != nil {
			return err
		}
		defer clear(updated)
		enc, err := format.Encrypt(key, o.name, updated)
		if err != nil {
			return err
		}
		return store.Write(base+"/secret.enc", enc, true)
	case "migrate":
		if format.IsV2(data) {
			return nil
		}
		enc, err := format.Encrypt(key, o.name, plain)
		if err != nil {
			return err
		}
		verified, err := format.Decrypt(key, o.name, enc)
		if err != nil {
			return err
		}
		defer clear(verified)
		if !bytes.Equal(verified, plain) {
			return errors.New("migration verification failed")
		}
		backup, err := store.Read(base+"/secret.enc.legacy", format.MaxContent+128)
		if err == nil {
			if !bytes.Equal(backup, data) {
				return errors.New("existing backup differs; original preserved")
			}
		} else if errors.Is(err, fs.ErrNotExist) {
			if err = store.Write(base+"/secret.enc.legacy", data, false); err != nil {
				return err
			}
		} else {
			return err
		}
		return store.Write(base+"/secret.enc", enc, true)
	}
	return errors.New("unknown mutation")
}

func (a *App) listUsers(store *safefs.Root) error {
	entries, err := store.List("users")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".pub")
		if err := safefs.Name(name, false); err != nil {
			return err
		}
		data, err := store.Read("users/"+e.Name(), MaxKey)
		if err != nil {
			return err
		}
		_, fp, err := a.Crypto.Public(data)
		if err != nil {
			return err
		}
		if _, err = fmt.Fprintf(a.Out, "%s\t%s\n", name, fp); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) listSecrets(store *safefs.Root, dir string) error {
	entries, err := store.List(dir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		p := dir + "/" + e.Name()
		if err := store.Check(p); err != nil {
			return err
		}
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".create-") {
			if err := safefs.Name(strings.TrimPrefix(p, "secrets/"), true); err != nil {
				return err
			}
			if err := a.listSecrets(store, p); err != nil {
				return err
			}
		}
	}
	if store.Check(dir+"/secret.enc") == nil {
		count := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".key.enc") {
				count++
			}
		}
		_, err = fmt.Fprintf(a.Out, "%s\t%d recipients\n", strings.TrimPrefix(dir, "secrets/"), count)
	}
	return err
}
