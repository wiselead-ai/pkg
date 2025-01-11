# PKG

A collection of Go packages with utility functions used by Wiselead AI.

They are open source and free to use.

## Installation

```zsh
go install github.com/wiselead-ai/pkg
```

## Usage

Import the packages in your Go files:

```go
import (
  "github.com/wiselead-ai/pkg/passwordutil"
  "github.com/wiselead-ai/pkg/idutil"
)
```

## Package Details

- **passwordutil**: Hashes and verifies passwords using Argon2.  
- **idutil**: Generates ULIDs as unique identifiers.

## Additional Usage Examples

### passwordutil

```go
package main

import (
  "fmt"

  "github.com/wiselead-ai/pkg/passwordutil"
)

func main() {
  hashed, _ := passwordutil.Hash("mySecret")
  match, _ := passwordutil.Verify("mySecret", hashed)
  fmt.Println("Password matches:", match)
}
```

### idutil

```go
package main

import (
  "fmt"

  "github.com/wiselead-ai/pkg/idutil"
)

func main() {
  id, _ := idutil.NewID()
  fmt.Println("Generated ULID:", id)
}
```
