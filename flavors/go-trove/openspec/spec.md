# Go module and binary distribution

### Requirement: Self-contained module and release matrix

Require Go 1.26.8 and CGO_ENABLED=0. Pin github.com/ProtonMail/gopenpgp/v3 v3.4.1,
github.com/ProtonMail/go-crypto v1.4.1, golang.org/x/sys v0.47.0 and
golang.org/x/term v0.45.0, github.com/cloudflare/circl v1.6.3 and
golang.org/x/crypto v0.56.0. Resolve and verify real go.sum entries before acceptance.
Use RFC4880 envelopes for retained GPG interoperability; content uses standard Go
AES-GCM/HKDF. Normal executable use requires no other installation or networking.

The release matrix SHALL be one authored JSON asset: linux/amd64, linux/arm64,
windows/amd64, windows/arm64, darwin/arm64. Package trove.exe in Windows ZIPs,
trove in Unix tar.gz, LICENSE and native user guidance in every archive, with one
SHA256SUMS. Filenames use x86_64/aarch64 and macos. Build reproducibly with
-trimpath and no host paths. Cross-compilation is build evidence; actual runtime,
DACL/reparse and ABI checks are required on each target before release.

#### Scenario: Contributor builds every required artifact

- **WHEN** a qualified module is packaged for release
- **THEN** all five target binaries and archives are built with CGO_ENABLED=0
- **AND** a single SHA256SUMS covers those archives
- **AND** no target is considered runtime-qualified until its own binary executes there

Dependencies and the toolchain SHALL pass a current reachable-symbol vulnerability
scan before candidate archives qualify; record the scanner version and database date.

### Requirement: Verified dependency checksum projection

The source generator SHALL write `source/go.sum` with the following exact verified
module checksums. These are public dependency-lock metadata obtained using Go's
module proxy and checksum database, then checked by `go mod verify`; they are not
inferred from library versions. A generated verifier SHALL build with
`-mod=readonly`, without modifying the admitted source tree. Add no unpinned module
or invented checksum. The contributor build SHALL select `GOTOOLCHAIN=go1.26.8`.

```text
github.com/ProtonMail/go-crypto v1.4.1 h1:9RfcZHqEQUvP8RzecWEUafnZVtEvrBVL9BiF67IQOfM=
github.com/ProtonMail/go-crypto v1.4.1/go.mod h1:e1OaTyu5SYVrO9gKOEhTc+5UcXtTUa+P3uLudwcgPqo=
github.com/ProtonMail/gopenpgp/v3 v3.4.1 h1:K7uUhSHSJxORZ+RuHpilTT6S4MA2whCRlXNwLqd0+ys=
github.com/ProtonMail/gopenpgp/v3 v3.4.1/go.mod h1:bGdV9f6edhmd581wzXsQCTKdH8bXBbyhkgDKPjwPc6U=
github.com/cloudflare/circl v1.6.3 h1:9GPOhQGF9MCYUeXyMYlqTR6a5gTrgR/fBLXvUgtVcg8=
github.com/cloudflare/circl v1.6.3/go.mod h1:2eXP6Qfat4O/Yhh8BznvKnJ+uzEoTQ6jVKJRn81BiS4=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/stretchr/testify v1.10.0 h1:Xv5erBjTwe/5IxqUQTdXv5kgmIvbHo3QQyRwhJsOfJA=
github.com/stretchr/testify v1.10.0/go.mod h1:r2ic/lqez/lEtzL7wO/rwa5dbSLXVDPFyf8C91i36aY=
golang.org/x/crypto v0.56.0 h1:GUh5Ii4J5jtcseSMiRqr1jXCNHoxjeV9Fmekc2oLy6Y=
golang.org/x/crypto v0.56.0/go.mod h1:OMW5y6CY9l38uPLmxU6l6pwcXp1obtLo3e6gT7gQR2I=
golang.org/x/sys v0.47.0 h1:o7XGOvZQCADBQQ4Y7VNq2dRWQR7JmOUW8Kxx4ZsNgWs=
golang.org/x/sys v0.47.0/go.mod h1:4GL1E5IUh+htKOUEOaiffhrAeqysfVGipDYzABqnCmw=
golang.org/x/term v0.45.0 h1:NwWyBmoJCbfTHpxrWoZ9C6/VxOf7ic219I8xZZFdrf0=
golang.org/x/term v0.45.0/go.mod h1:9aqxs0blBcrm/n0L9QW0aRVD+ktan8ssZromtqJC43w=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
```

#### Scenario: Isolated generation emits an immutable module lock

- **WHEN** source is generated without module-network access
- **THEN** go.sum contains the verified checksum projection above
- **AND** `go test -mod=readonly ./...` can use the pinned modules without changing source
