# Go Project Template
This template implements a **Package-Oriented Architecture**. It prioritizes Go idioms over rigid enterprise patterns, following the lead of major projects like **Kubernetes** and **Terraform**.


## Core Philosophy
- **Accept Interfaces, Return Structs:** We define interfaces where they are consumed (in ports.go), not where they are implemented.
- **Encapsulation over Layering:** Logic is grouped by business domain (e.g., user, order) rather than technical role (service, controller).
- **Dependency Orchestration:** Cross-package logic is handled at the api/ layer to prevent circular dependencies.


## Project Structure 
```text
/myapp
├── cmd/
│    ├── server/
│    │    └── main.go              // App entry point & dependency injection (wiring) 
│    └── worker/
│         └── main.go
├── internal/
│    ├── user/                     // Domain-specific package 
│    │    ├── model.go
│    │    ├── service.go           // Domain business logic
│    │    ├── service_test.go
│    │    ├── ports.go             // Requirements defined as Interfaces
│    │    └── repository/
│    │         ├── pg.go
│    │         └── pg_model.go
│    ├── order/
│    │    ├── model.go
│    │    ├── service.go
│    │    ├── service_test.go
│    │    ├── ports.go
│    │    └── repository/
│    │         ├── pg.go
│    │         └── pg_model.go
│    ├── usecase/                  // Orchestration layer for multi-domain business logic flows
│    │    ├── checkout/
│    │    │    ├── service.go
│    │    │    └── ports.go
│    │    └── refund/
│    │         ├── service.go
│    │         └── ports.go
│    ├── shared/                   // Shared model
│    │    ├── pagination.go
│    │    └── money.go
│    └── infra/                    // Infra integrations code
│         ├── postgres.go
│         └── redis.go
├── pkg/                           // Reusable library code (Logger, Crypto) 
│    ├── logger/
│    └── crypto/
└── api/                           // Transport layer (REST Handlers, gRPC, Middleware) 
     └── rest/
          ├── user_handler.go
          ├── checkout_handler.go
          └── routes.go
```
## Directory Explanations
### cmd/
Entry points for all runnable binaries. Each subdirectory maps to one compiled binary.  

| File or Dir | Purpose |
|-------------|---------|
| cmd/server/main.go | App entry point. Reads config, initializes infra, wires all dependencies, starts HTTP server. |
| cmd/worker/main.go | Optional, separate binary for background jobs or queue consumers. Shares the same internal/ packages. |

### main.go is pure wiring, no business logic:
```go
gofunc main() {
    cfg := config.Load()
    db  := infra.NewMySQLPool(cfg)
    rdb := infra.NewRedisClient(cfg)

    userRepo    := userrepo.New(db)
    userSvc     := user.NewService(userRepo)
    checkoutSvc := checkout.NewService(userSvc, ...)

    r := chi.NewRouter()
    rest.RegisterRoutes(r, userSvc, checkoutSvc)
    http.ListenAndServe(cfg.Addr, r)
}
```

### internal/{domain}/ (e.g. user/, order/)
One directory per domain. Each domain is fully self-contained with its own models, business logic, interfaces, and repository implementation.

| File | Purpose |
|------|---------|
| model.go | Business-level structs (User, Order, etc.). Pure Go, no db:"" tags, no infra concerns. |
| service.go | Core business logic. Concrete struct + methods. Depends only on interfaces from ports.go, never on infra directly. |
| service_test.go | Unit tests for service logic. Uses mock implementations of ports interfaces. |
| ports.go | Interfaces that the domain requires (e.g. UserRepository, EmailSender). Defined by the domain, implemented by infra. |
| repository/pg.go | Postgres implementation of UserRepository. Translates between domain model and db model. |
| repository/pg_model.go | DB-layer structs with `db:""` tags. Also contains toDomain() / fromDomain() mapping functions. |

**Example ports.go:**  
```go
// internal/user/ports.go
type Repository interface {
    GetByID(ctx context.Context, id string) (*User, error)
    Create(ctx context.Context, u *User) error
}

type EmailSender interface {
    SendWelcome(ctx context.Context, email string) error
}
```

**Example repository/pg_model.go:**  
```go
// internal/user/repository/pg_model.go
type pgUser struct {
    ID        string    `db:"id"`
    Email     string    `db:"email"`
    CreatedAt time.Time `db:"created_at"`
}

func (p pgUser) toDomain() *user.User {
    return &user.User{ID: p.ID, Email: p.Email}
}

func fromDomain(u *user.User) pgUser {
    return pgUser{ID: u.ID, Email: u.Email}
}
```

### internal/usecase/  
Orchestration layer for multi-domain flows that contain real business logic. Prevents business rules from leaking into the transport (handler) layer.  
Each subdirectory is one use case, a user-facing operation that spans multiple domains.  
| File | Purpose |
|------|---------|
| usecase/checkout/service.go | Orchestrates user, order, payment domains for the checkout flow. Business decisions live here. | 
| usecase/checkout/ports.go | Interfaces for each domain the usecase depends on ```(UserProvider, OrderCreator, PaymentCharger)```. Injected via constructor. |


### internal/shared/  
Shared primitive types with no business logic, imported by multiple domains. Keep this small and stable.  
✅ Good candidates: Money, Pagination, TimeRange, Address, AuditInfo  
❌ Unsuitable candidates: User, Order, these are domain-owned, not shared primitives.  

### internal/infra/  
App-specific infrastructure initialization. Reads your config, knows your environment, creates concrete clients.  
Lives in internal/ (not pkg/) because it contains app-specific configuration knowledge.

```go
// internal/infra/mysql.go
func NewMySQLPool(cfg Config) *sqlx.DB {
    dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s",
        cfg.DB.User, cfg.DB.Pass, cfg.DB.Host, cfg.DB.Name)
    db, err := sqlx.Open("mysql", dsn)
    // configure pool, timeouts, etc.
    return db
}
```

### pkg/
Generic, reusable utilities with zero business context. Safe for any project to import.  
✅ Good candidates: logger wrapper, crypto helpers, HTTP client builder, pagination helpers  
❌ Bad candidates: anything that imports your **domain types or reads your app config**  

### api/
Transport layer. Handles HTTP/gRPC concerns: parsing requests, calling services, writing responses. Should contain no business logic.  
| File | Purpose |  
|------|---------|  
| rest/user_handler.go | HTTP handler for single-domain user operations. Calls **user.Service** directly. |  
| rest/checkout_handler.go | HTTP handler for the checkout flow. Calls **usecase/checkout.Service**, not individual domain services. |  

## Key Design Rules
**1. Avoiding Circular Dependencies**  
To prevent the common ```import cycle not allowed``` error:  
**A. Shared Types:** All structs used by more than one package live in ```internal/shared```.  
**B. Orchestration:** If a feature requires calling both ```user``` and ```order``` services, that logic lives in the ```internal/usecase``` for a multi-domains flow orchestrator.  

**2. Mocking and Testability**  
Testability is achieved through ```Constructor Injection```. Each service in ```internal/``` defines its dependencies as interfaces in ```ports.go```.  
During testing, you simply pass a mock implementation into the service constructor.  

**3. The ```internal/``` Boundary**  
Code inside ```internal/``` cannot be imported by any code outside this project. 
This ensures your core business logic remains private and cannot be "leaked" into external tools or libraries.  

## Orchestration Strategy
### Orchestrate at Usecase Layer - Recommended
Use this when the orchestration contains **real business decisions** (discounts, fraud checks, conditional flows). Keeps the handler thin and the logic testable independently of HTTP.  
### Step 1: Define ports in usecase/checkout/ports.go
```go
// internal/usecase/checkout/ports.go
package checkout

type UserProvider interface {
    GetByID(ctx context.Context, id string) (UserInfo, error)
}

// UserInfo is checkout's own view of a user — only what it needs
type UserInfo struct {
    ID             string
    Email          string
    MembershipTier string
}

type OrderCreator interface {
    Create(ctx context.Context, input CreateOrderInput) (OrderResult, error)
}

type PaymentCharger interface {
    Charge(ctx context.Context, input ChargeInput) (ChargeResult, error)
}
```

### Step 2: Implement orchestration in usecase/checkout/service.go
```go
// internal/usecase/checkout/service.go
package checkout

type Service struct {
    users    UserProvider
    orders   OrderCreator
    payments PaymentCharger
}

func NewService(u UserProvider, o OrderCreator, p PaymentCharger) *Service {
    return &Service{users: u, orders: o, payments: p}
}

func (s *Service) Checkout(ctx context.Context, input Input) (Result, error) {
    user, _ := s.users.GetByID(ctx, input.UserID)

    // Business logic lives here, not in the handler
    discount := 0
    if strings.Contains(strings.ToLower(user.Email), "vip") {
        discount = 10
    }

    order, _ := s.orders.Create(ctx, CreateOrderInput{
        Items:    input.Items,
        Discount: discount,
    })

    payment, _ := s.payments.Charge(ctx, ChargeInput{
        Amount: order.Total,
        UserID: user.ID,
    })

    return Result{OrderID: order.ID, PaymentID: payment.ID}, nil
}
```

### Step 3: Handler to focus on transport level code
```go
// api/rest/checkout_handler.go
func (h *CheckoutHandler) Checkout(w http.ResponseWriter, r *http.Request) {
    input := parseCheckoutRequest(r)
    result, err := h.checkoutSvc.Checkout(r.Context(), input)
    if err != nil {
        writeError(w, err)
        return
    }
    writeJSON(w, http.StatusOK, result)
}
```

### Step 4: Wire it all in cmd/server/main.go
```go
db  := infra.NewMySQLPool(cfg)
rdb := infra.NewRedisClient(cfg)

// Domain layer
userRepo   := userrepo.New(db)
orderRepo  := orderrepo.New(db)
userSvc    := user.NewService(userRepo)
orderSvc   := order.NewService(orderRepo)
paymentSvc := payment.NewService(cfg.PaymentKey)

// Usecase layer — receives domain services via interface
checkoutSvc := checkout.NewService(userSvc, orderSvc, paymentSvc)

// Transport layer
r := chi.NewRouter()
rest.RegisterRoutes(r, userSvc, checkoutSvc)
http.ListenAndServe(cfg.Addr, r)
```

## Avoiding Cyclic Dependencies
The most common mistake is having two domains import each other. This is always a design smell, not a Go limitation.  
| Pattern | Risk | Fix |  
|---------|------|-----|
| ```order``` imports ```user.User``` directly | Cyclic if user also needs ```order``` | Use ```UserID``` string instead, or define ```UserInfo``` in ```order/ports.go``` | 
| Business logic in handler calls several domains | Logic duplicated across handlers | Extract into ```internal/usecase/<flow>/``` |
| Shared domain types in ```internal/shared/``` | ```shared/``` becomes a dumping ground | Only truly generic types: ```Money, Pagination, TimeRange``` |

## The Reference Pattern
When domain A needs to reference domain B's entity, use an **ID string** instead of embedding the full type:  
```go
// internal/order/model.go
type Order struct {
    ID     string
    UserID string    // reference, not user.User
    Items  []OrderItem
    Total  int
}
```
If ```order``` service genuinely needs user data, it declares a minimal interface in its own ```ports.go``` and receives a concrete implementation via dependency injection, never by importing the ```user``` package directly.  

## Example Runtime
This template now includes:
- `Gin` HTTP server
- `Postgres` persistence
- `user` login and profile lookup
- `order` CRUD
- `checkout` orchestration across user and order
- `Dockerfile` and `docker-compose.yml`

### Environment
The app reads config from `.env` or process environment variables.

Important variables:
- `SERVER_HOST`
- `SERVER_PORT`
- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`
- `DB_SSLMODE`

### Demo User
On first boot, the server seeds a demo user if it does not exist.

- Email: `vip@example.com`
- Password: `password123`
- Checkout discount: user email contains `vip`

### API Endpoints
- `POST /api/v1/users/login`
- `GET /api/v1/users/:id`
- `POST /api/v1/orders`
- `GET /api/v1/orders`
- `GET /api/v1/orders/:id`
- `PUT /api/v1/orders/:id`
- `DELETE /api/v1/orders/:id`
- `POST /api/v1/checkout`

## Quick Decision Guide
| Question | Answer |
|----------|--------|
| Where do business models live? | ```internal/<domain>/model.go``` colocated with the domain, not in a shared folder |  
| Where do DB/infra models live? | ```internal/<domain>/repository/pg_model.go``` next to the adapter that uses them |  
| Where does infra init go? | ```internal/infra/``` app-specific, reads config, not in ```pkg/``` |  
| Where does reusable generic code go? | ```pkg/``` only if it has zero business context and could live in any project |  
| Multi-domain flow, where does logic go? | ```internal/usecase/<flow>/``` if there are business decisions; handler level if it is simple delegation |  
| Domain A needs data from domain B? | Define an interface in domain A's ```ports.go```. Never import domain B's package directly. |
