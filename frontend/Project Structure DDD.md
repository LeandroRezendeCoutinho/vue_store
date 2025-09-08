# Vue DDD

```
src/
├── core/                          # Shared kernel
│   ├── domain/                    # Core domain concepts
│   │   ├── value-objects/         # Value objects (e.g., Money, Email)
│   │   ├── entities/              # Core entities (e.g., User, Product)
│   │   └── specifications/        # Business rules and specifications
│   ├── application/               # Application services layer
│   │   └── ports/                 # Interfaces (ports) for external systems
│   └── infrastructure/            # Infrastructure implementations
│       ├── api/                   # API communication implementations
│       └── storage/               # Browser storage implementations
│
├── modules/                       # Bounded contexts
│   ├── identity/                  # Identity & access context
│   │   ├── domain/
│   │   │   ├── entities/          # User, Role, Permission
│   │   │   ├── value-objects/     # Email, Password, UserStatus
│   │   │   └── services/          # AuthenticationService, AuthorizationService
│   │   ├── application/
│   │   │   ├── use-cases/         # RegisterUser, LoginUser, ChangePassword
│   │   │   └── ports/             # IUserRepository, IAuthService
│   │   ├── infrastructure/
│   │   │   └── persistence/       # UserRepository, SessionStorage
│   │   └── presentation/          # Vue components for this context
│   │       ├── components/
│   │       │   ├── LoginForm.vue
│   │       │   ├── RegisterForm.vue
│   │       │   └── UserProfile.vue
│   │       └── views/
│   │           ├── LoginView.vue
│   │           └── ProfileView.vue
│   │
│   ├── catalog/                   # Product catalog context
│   │   ├── domain/
│   │   │   ├── entities/          # Product, Category, Inventory
│   │   │   ├── value-objects/     # Price, SKU, ProductStatus
│   │   │   └── services/          # ProductService, InventoryService
│   │   ├── application/
│   │   │   ├── use-cases/         # CreateProduct, UpdateProduct, SearchProducts
│   │   │   └── ports/             # IProductRepository, ICategoryRepository
│   │   ├── infrastructure/
│   │   │   └── persistence/       # ProductRepository, CategoryRepository
│   │   └── presentation/
│   │       ├── components/
│   │       │   ├── ProductCard.vue
│   │       │   ├── ProductList.vue
│   │       │   └── ProductFilter.vue
│   │       └── views/
│   │           ├── ProductListView.vue
│   │           └── ProductDetailView.vue
│   │
│   └── orders/                    # Order management context
│       ├── domain/
│       │   ├── entities/          # Order, OrderItem, Payment
│       │   ├── value-objects/     # OrderStatus, Address, PaymentMethod
│       │   └── services/          # OrderService, PaymentService
│       ├── application/
│       │   ├── use-cases/         # CreateOrder, ProcessPayment, CancelOrder
│       │   └── ports/             # IOrderRepository, IPaymentGateway
│       ├── infrastructure/
│       │   └── persistence/       # OrderRepository, PaymentAdapter
│       └── presentation/
│           ├── components/
│           │   ├── OrderSummary.vue
│           │   ├── OrderItem.vue
│           │   └── CheckoutForm.vue
│           └── views/
│               ├── OrderHistoryView.vue
│               └── CheckoutView.vue
│
├── shared/                        # Shared components and utilities
│   ├── ui/                        # Reusable UI components
│   │   ├── buttons/
│   │   ├── forms/
│   │   ├── modals/
│   │   └── layout/
│   ├── utils/                     # Utility functions
│   │   ├── formatters.js          # Date, currency formatting
│   │   ├── validators.js          # Validation rules
│   │   └── helpers.js             # Helper functions
│   └── services/                  # Shared services
│       ├── api.js                 # API service
│       └── event-bus.js           # Event bus for cross-context communication
│
├── router/                        # Vue Router configuration
│   ├── index.js                   # Main router configuration
│   └── routes/                    # Route definitions per context
│       ├── identity.js
│       ├── catalog.js
│       └── orders.js
│
├── store/                         # Vuex store
│   ├── index.js                   # Main store configuration
│   └── modules/                   # Vuex modules organized by context
│       ├── identity.js
│       ├── catalog.js
│       └── orders.js
│
├── App.vue                        # Root component
└── main.js                        # Application entry point
```
