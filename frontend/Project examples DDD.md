This project structure follows **Domain-Driven Design (DDD)** and **Clean Architecture** principles, organized to maintain separation of concerns and business logic isolation. Let me break down each component:

## 🏗️ **Overall Architecture**
This is a **frontend application** with domain-driven design, where the `core/` directory contains the business logic independent of any framework or UI.

---

## 📁 **core/** - Shared Kernel
The heart of the application containing business logic that can be shared across different parts of the system.

### **📂 domain/** - Domain Layer
Contains the business concepts and rules - the **what** of your application.

#### **📂 value-objects/**
- **Purpose**: Represent concepts without identity, defined by their attributes
- **Examples**:
  ```typescript
  // Money value object
  class Money {
    constructor(public amount: number, public currency: string) {}
    
    add(other: Money): Money {
      if (this.currency !== other.currency) throw new Error('Currency mismatch');
      return new Money(this.amount + other.amount, this.currency);
    }
  }
  
  // Email value object
  class Email {
    constructor(public value: string) {
      if (!this.isValid(value)) throw new Error('Invalid email');
    }
  }
  ```
- **Characteristics**: Immutable, self-validating, no identity

#### **📂 entities/**
- **Purpose**: Objects with distinct identity that evolve over time
- **Examples**:
  ```typescript
  class User {
    constructor(
      public id: UserId,           // Identity
      public email: Email,         // Value object
      public name: string
    ) {}
    
    changeEmail(newEmail: Email): void {
      this.email = newEmail;
      this.addDomainEvent(new EmailChangedEvent(this.id));
    }
  }
  ```
- **Characteristics**: Have identity, contain business logic, track changes

#### **📂 specifications/**
- **Purpose**: Encapsulate business rules and constraints
- **Examples**:
  ```typescript
  class PremiumUserSpecification {
    isSatisfiedBy(user: User): boolean {
      return user.subscription.isPremium && 
             user.accountBalance.isPositive();
    }
  }
  ```

---

### **📂 application/** - Application Layer
Orchestrates use cases and defines contracts with external systems.

#### **📂 ports/** - Interfaces (Hexagonal Architecture)
- **Purpose**: Define **abstractions** that the application needs from the outside world
- **Types**:
  - **Input Ports**: Interfaces for driving the application (use cases)
  - **Output Ports**: Interfaces for external systems to implement

**Example Port Interfaces**:
```typescript
// Input port - for executing use cases
interface CreateUserUseCase {
  execute(command: CreateUserCommand): Promise<User>;
}

// Output ports - what the application needs from outside
interface UserRepository {
  save(user: User): Promise<void>;
  findById(id: UserId): Promise<User | null>;
}

interface EmailService {
  sendWelcomeEmail(email: Email): Promise<void>;
}
```

---

### **📂 infrastructure/** - Infrastructure Layer
**Concrete implementations** of the ports defined in the application layer.

#### **📂 api/** - External API Communications
- **Purpose**: Implement API-related port interfaces
- **Examples**:
  ```typescript
  class HttpUserRepository implements UserRepository {
    async save(user: User): Promise<void> {
      await fetch('/api/users', {
        method: 'POST',
        body: JSON.stringify(user)
      });
    }
  }
  
  class RestEmailService implements EmailService {
    async sendWelcomeEmail(email: Email): Promise<void> {
      // Actual HTTP implementation
    }
  }
  ```

#### **📂 storage/** - Browser Storage Implementations
- **Purpose**: Implement storage-related port interfaces using browser APIs
- **Examples**:
  ```typescript
  class LocalStorageUserRepository implements UserRepository {
    async save(user: User): Promise<void> {
      localStorage.setItem(`user_${user.id}`, JSON.stringify(user));
    }
  }
  ```

---

## 🔄 **Data Flow**
1. **UI Layer** (not shown) calls application services
2. **Application Layer** orchestrates using domain objects
3. **Domain Layer** contains business logic
4. **Infrastructure Layer** provides concrete implementations of ports

## 🎯 **Key Benefits**
- **Testability**: Easy to mock ports for testing
- **Framework Independence**: Core logic works with any UI framework
- **Maintainability**: Clear boundaries between concerns
- **Flexibility**: Easy to swap implementations (API ↔ LocalStorage)

## 🚀 **Typical Usage**
```typescript
// In your UI component (React/Vue/Angular)
const userService = new UserApplicationService(
  new HttpUserRepository(),      // Infrastructure
  new RestEmailService()         // Infrastructure
);

const user = await userService.createUser({
  email: "john@example.com",
  name: "John Doe"
});
```

This structure ensures your business logic remains pure and independent of technical implementation details!

This structure implements **Bounded Contexts** and follows a **modular monolith** approach with vertical slicing. Let me break down each component in detail:

---

## 🏗️ **modules/** - Bounded Contexts
**Purpose**: Organize the application around business domains rather than technical layers. Each module represents a distinct business capability.

---

## 🔐 **identity/** - Identity & Access Context
A complete vertical slice handling all identity, authentication, and authorization concerns.

### **📂 domain/** - Identity Domain Logic

#### **📂 entities/** - Core Identity Concepts
- **User**: 
  ```typescript
  class User extends Entity<UserId> {
    constructor(
      id: UserId,
      public email: Email,
      public password: HashedPassword,
      public status: UserStatus,
      public roles: Role[] = []
    ) {}
    
    activate(): void {
      this.status = UserStatus.ACTIVE;
    }
    
    hasPermission(permission: Permission): boolean {
      return this.roles.some(role => role.hasPermission(permission));
    }
  }
  ```

- **Role**:
  ```typescript
  class Role extends Entity<RoleId> {
    constructor(
      id: RoleId,
      public name: string,
      public permissions: Permission[] = []
    ) {}
  }
  ```

- **Permission**: Enum or value object defining access rights

#### **📂 value-objects/** - Identity-Specific Values
```typescript
// Email - with validation specific to identity context
class Email extends ValueObject {
  constructor(public value: string) {
    super();
    if (!this.isValidEmail(value)) {
      throw new InvalidEmailError(value);
    }
  }
}

// Password - with strength requirements
class Password extends ValueObject {
  constructor(public value: string) {
    super();
    if (!this.meetsComplexityRequirements(value)) {
      throw new WeakPasswordError();
    }
  }
}

// UserStatus - domain-specific states
enum UserStatus {
  PENDING = 'pending',
  ACTIVE = 'active',
  SUSPENDED = 'suspended',
  DELETED = 'deleted'
}
```

#### **📂 services/** - Domain Services
**Purpose**: Operations that don't naturally fit entities/value objects

```typescript
// AuthenticationService - pure domain logic
class AuthenticationService {
  authenticate(user: User, plainPassword: string): boolean {
    if (user.status !== UserStatus.ACTIVE) {
      throw new UserNotActiveError();
    }
    return user.password.matches(plainPassword);
  }
}

// AuthorizationService - permission checks
class AuthorizationService {
  canAccessResource(user: User, resource: Resource, action: Action): boolean {
    return user.roles.some(role => 
      role.permissions.some(permission => 
        permission.grantsAccess(resource, action)
      )
    );
  }
}
```

---

### **📂 application/** - Identity Use Cases

#### **📂 use-cases/** - Application-Specific Operations
**Purpose**: Orchestrate domain objects to fulfill user intentions

```typescript
// RegisterUser - complete user registration flow
class RegisterUserUseCase {
  constructor(
    private userRepository: IUserRepository,
    private authService: IAuthService
  ) {}

  async execute(command: RegisterUserCommand): Promise<UserDto> {
    // Validate business rules
    if (await this.userRepository.existsByEmail(command.email)) {
      throw new EmailAlreadyExistsError();
    }

    // Create domain objects
    const email = new Email(command.email);
    const password = new Password(command.password);
    const hashedPassword = await this.authService.hashPassword(password);
    
    const user = new User(
      UserId.generate(),
      email,
      hashedPassword,
      UserStatus.PENDING
    );

    // Persist
    await this.userRepository.save(user);
    
    // Trigger side effects
    await this.authService.sendActivationEmail(user);
    
    return UserMapper.toDTO(user);
  }
}

// LoginUser - authentication flow
class LoginUserUseCase {
  async execute(command: LoginCommand): Promise<Session> {
    const user = await this.userRepository.findByEmail(command.email);
    if (!user) {
      throw new InvalidCredentialsError();
    }

    const isValid = await this.authService.verifyPassword(
      user.password, 
      command.password
    );
    
    if (!isValid) {
      throw new InvalidCredentialsError();
    }

    return this.authService.createSession(user);
  }
}
```

#### **📂 ports/** - Identity Context Contracts
```typescript
// Input ports (interfaces for use cases)
interface IRegisterUserUseCase {
  execute(command: RegisterUserCommand): Promise<UserDto>;
}

// Output ports (dependencies the application needs)
interface IUserRepository {
  save(user: User): Promise<void>;
  findById(id: UserId): Promise<User | null>;
  findByEmail(email: Email): Promise<User | null>;
  existsByEmail(email: Email): Promise<boolean>;
}

interface IAuthService {
  hashPassword(password: Password): Promise<HashedPassword>;
  verifyPassword(hashed: HashedPassword, plain: string): Promise<boolean>;
  createSession(user: User): Promise<Session>;
  sendActivationEmail(user: User): Promise<void>;
}
```

---

### **📂 infrastructure/** - Identity Technical Implementations

#### **📂 persistence/** - Data Access Implementations
```typescript
// UserRepository - implements the port interface
class UserRepository implements IUserRepository {
  async findByEmail(email: Email): Promise<User | null> {
    const userData = await db.users.findOne({ email: email.value });
    return userData ? UserMapper.toDomain(userData) : null;
  }

  async save(user: User): Promise<void> {
    const persistenceModel = UserMapper.toPersistence(user);
    await db.users.save(persistenceModel);
  }
}

// SessionStorage - browser session management
class SessionStorage implements ISessionStorage {
  setSession(session: Session): void {
    localStorage.setItem('auth_token', session.token);
    localStorage.setItem('user_id', session.userId.value);
  }

  getCurrentSession(): Session | null {
    const token = localStorage.getItem('auth_token');
    return token ? new Session(token) : null;
  }
}
```

---

### **📂 presentation/** - Identity UI Components

#### **📂 components/** - Reusable Identity Components
```vue
<!-- LoginForm.vue -->
<template>
  <form @submit.prevent="handleLogin">
    <input v-model="email" type="email" placeholder="Email">
    <input v-model="password" type="password" placeholder="Password">
    <button :disabled="isLoading">Login</button>
    <div v-if="error" class="error">{{ error.message }}</div>
  </form>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useLogin } from '../composables/useLogin';

const { login, isLoading, error } = useLogin();

const email = ref('');
const password = ref('');

const handleLogin = async () => {
  await login({
    email: email.value,
    password: password.value
  });
};
</script>
```

#### **📂 views/** - Full Identity Pages
```vue
<!-- LoginView.vue -->
<template>
  <div class="login-view">
    <h1>Welcome Back</h1>
    <LoginForm />
    <p>Don't have an account? <router-link to="/register">Register</router-link></p>
  </div>
</template>
```

---

## 🔄 **Complete Data Flow Example**

```typescript
// 1. Presentation Layer (Vue component calls use case)
const registerUser = async () => {
  const useCase = container.get<IRegisterUserUseCase>('RegisterUserUseCase');
  
  try {
    const user = await useCase.execute({
      email: 'user@example.com',
      password: 'securePassword123'
    });
    
    // Navigate to success page
    router.push('/profile');
  } catch (error) {
    // Handle domain errors
    showError(error.message);
  }
};

// 2. Application Layer (use case orchestrates)
class RegisterUserUseCase implements IRegisterUserUseCase {
  constructor(
    @inject('IUserRepository') private userRepository: IUserRepository,
    @inject('IAuthService') private authService: IAuthService
  ) {}

  async execute(command: RegisterUserCommand): Promise<UserDto> {
    // Business logic flow...
  }
}
```

---

## 🎯 **Key Benefits of This Structure**

1. **High Cohesion**: All identity-related code lives together
2. **Loose Coupling**: Other modules depend on contracts, not implementations
3. **Independent Development**: Identity team can work independently
4. **Testability**: Easy to mock dependencies
5. **Clear Boundaries**: Prevents identity concerns from leaking into other contexts

## 🧪 **Testing Strategy**
```typescript
// Testing use cases in isolation
describe('RegisterUserUseCase', () => {
  it('should register user with valid data', async () => {
    const mockRepo = mock<IUserRepository>();
    const useCase = new RegisterUserUseCase(mockRepo);
    
    await useCase.execute(validCommand);
    
    expect(mockRepo.save).toHaveBeenCalledWith(expect.any(User));
  });
});
```

This structure enables **domain-focused development** where each bounded context can evolve independently while maintaining clear contracts between them!

Here's how to implement this Domain-Driven Design structure in pure JavaScript:

## 🏗️ **Project Structure Setup**

```
src/
├── core/
│   ├── domain/
│   │   ├── value-objects/
│   │   ├── entities/
│   │   └── specifications/
│   ├── application/
│   │   └── ports/
│   └── infrastructure/
│       ├── api/
│       └── storage/
├── modules/
│   └── identity/
│       ├── domain/
│       │   ├── entities/
│       │   ├── value-objects/
│       │   └── services/
│       ├── application/
│       │   ├── use-cases/
│       │   └── ports/
│       ├── infrastructure/
│       │   └── persistence/
│       └── presentation/
│           ├── components/
│           └── views/
└── shared/
    ├── errors/
    └── utils/
```

## 🔧 **Core Domain Implementation**

### **📁 shared/errors/domain-errors.js**
```javascript
class DomainError extends Error {
  constructor(message) {
    super(message);
    this.name = this.constructor.name;
  }
}

class InvalidEmailError extends DomainError {}
class WeakPasswordError extends DomainError {}
class UserNotActiveError extends DomainError {}
class InvalidCredentialsError extends DomainError {}
class EmailAlreadyExistsError extends DomainError {}

export {
  DomainError,
  InvalidEmailError,
  WeakPasswordError,
  UserNotActiveError,
  InvalidCredentialsError,
  EmailAlreadyExistsError
};
```

### **📁 shared/utils/value-object.js**
```javascript
export class ValueObject {
  equals(other) {
    if (other === null || other === undefined) {
      return false;
    }
    if (other.constructor !== this.constructor) {
      return false;
    }
    return JSON.stringify(this) === JSON.stringify(other);
  }

  toString() {
    return JSON.stringify(this);
  }
}
```

## 🔐 **Identity Module Implementation**

### **📁 modules/identity/domain/value-objects/**

#### **email.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';
import { InvalidEmailError } from '../../../../shared/errors/domain-errors.js';

export class Email extends ValueObject {
  constructor(value) {
    super();
    this.value = value.trim().toLowerCase();
    this.#validate();
  }

  #validate() {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(this.value)) {
      throw new InvalidEmailError(`Invalid email format: ${this.value}`);
    }
  }

  getLocalPart() {
    return this.value.split('@')[0];
  }

  getDomain() {
    return this.value.split('@')[1];
  }
}
```

#### **password.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';
import { WeakPasswordError } from '../../../../shared/errors/domain-errors.js';

export class Password extends ValueObject {
  constructor(value) {
    super();
    this.value = value;
    this.#validate();
  }

  #validate() {
    if (this.value.length < 8) {
      throw new WeakPasswordError('Password must be at least 8 characters long');
    }
    
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(this.value)) {
      throw new WeakPasswordError(
        'Password must contain at least one lowercase letter, one uppercase letter, and one number'
      );
    }
  }
}

export class HashedPassword extends ValueObject {
  constructor(hash, salt) {
    super();
    this.hash = hash;
    this.salt = salt;
  }

  async matches(plainPassword) {
    // In a real app, you'd use a proper hashing library like bcrypt
    const testHash = await this.#hashPassword(plainPassword, this.salt);
    return this.hash === testHash;
  }

  async #hashPassword(password, salt) {
    // Simplified hashing - use a proper library in production
    const encoder = new TextEncoder();
    const data = encoder.encode(password + salt);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
```

#### **user-status.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';

export class UserStatus extends ValueObject {
  static PENDING = new UserStatus('pending');
  static ACTIVE = new UserStatus('active');
  static SUSPENDED = new UserStatus('suspended');
  static DELETED = new UserStatus('deleted');

  constructor(value) {
    super();
    this.value = value;
  }

  toString() {
    return this.value;
  }

  canLogin() {
    return this.value === UserStatus.ACTIVE.value;
  }
}
```

### **📁 modules/identity/domain/entities/**

#### **entity.js** (Base class)
```javascript
export class Entity {
  constructor(id) {
    if (new.target === Entity) {
      throw new Error('Entity is an abstract class and cannot be instantiated directly');
    }
    this.id = id;
    this.domainEvents = [];
  }

  addDomainEvent(event) {
    this.domainEvents.push(event);
  }

  clearDomainEvents() {
    this.domainEvents = [];
  }

  getDomainEvents() {
    return [...this.domainEvents];
  }

  equals(other) {
    if (other === null || other === undefined) {
      return false;
    }
    if (other.constructor !== this.constructor) {
      return false;
    }
    return this.id === other.id;
  }
}
```

#### **user-id.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';

export class UserId extends ValueObject {
  constructor(value) {
    super();
    this.value = value;
  }

  static generate() {
    return new UserId(`user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`);
  }

  toString() {
    return this.value;
  }
}
```

#### **user.js**
```javascript
import { Entity } from './entity.js';
import { UserId } from './user-id.js';
import { UserStatus } from '../value-objects/user-status.js';

export class User extends Entity {
  constructor(id, email, hashedPassword, status = UserStatus.PENDING, roles = []) {
    super(id);
    this.email = email;
    this.hashedPassword = hashedPassword;
    this.status = status;
    this.roles = roles;
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  activate() {
    this.status = UserStatus.ACTIVE;
    this.updatedAt = new Date();
    this.addDomainEvent({ type: 'USER_ACTIVATED', userId: this.id });
  }

  suspend() {
    this.status = UserStatus.SUSPENDED;
    this.updatedAt = new Date();
    this.addDomainEvent({ type: 'USER_SUSPENDED', userId: this.id });
  }

  changeEmail(newEmail) {
    this.email = newEmail;
    this.updatedAt = new Date();
    this.addDomainEvent({ type: 'EMAIL_CHANGED', userId: this.id, newEmail });
  }

  canLogin() {
    return this.status.canLogin();
  }

  hasPermission(permission) {
    return this.roles.some(role => role.hasPermission(permission));
  }
}
```

### **📁 modules/identity/domain/services/**

#### **authentication-service.js**
```javascript
import { UserNotActiveError, InvalidCredentialsError } from '../../../../shared/errors/domain-errors.js';

export class AuthenticationService {
  authenticate(user, plainPassword) {
    if (!user.canLogin()) {
      throw new UserNotActiveError(`User ${user.id} is not active`);
    }

    return user.hashedPassword.matches(plainPassword);
  }

  async createSession(user) {
    const session = {
      userId: user.id,
      token: this.#generateToken(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      createdAt: new Date()
    };

    return session;
  }

  #generateToken() {
    return `token_${Date.now()}_${Math.random().toString(36).substr(2)}`;
  }
}
```

### **📁 modules/identity/application/ports/**

#### **user-repository.js**
```javascript
export class IUserRepository {
  async save(user) {
    throw new Error('Method not implemented');
  }

  async findById(id) {
    throw new Error('Method not implemented');
  }

  async findByEmail(email) {
    throw new Error('Method not implemented');
  }

  async existsByEmail(email) {
    throw new Error('Method not implemented');
  }

  async delete(id) {
    throw new Error('Method not implemented');
  }
}
```

#### **auth-service.js**
```javascript
export class IAuthService {
  async hashPassword(password) {
    throw new Error('Method not implemented');
  }

  async verifyPassword(hashedPassword, plainPassword) {
    throw new Error('Method not implemented');
  }

  async createSession(user) {
    throw new Error('Method not implemented');
  }

  async sendActivationEmail(user) {
    throw new Error('Method not implemented');
  }
}
```

### **📁 modules/identity/application/use-cases/**

#### **register-user-use-case.js**
```javascript
import { Email } from '../../domain/value-objects/email.js';
import { Password } from '../../domain/value-objects/password.js';
import { User } from '../../domain/entities/user.js';
import { UserId } from '../../domain/entities/user-id.js';
import { UserStatus } from '../../domain/value-objects/user-status.js';
import { EmailAlreadyExistsError } from '../../../../shared/errors/domain-errors.js';

export class RegisterUserUseCase {
  constructor(userRepository, authService) {
    this.userRepository = userRepository;
    this.authService = authService;
  }

  async execute(command) {
    // Validate input
    const email = new Email(command.email);
    const password = new Password(command.password);

    // Check business rules
    if (await this.userRepository.existsByEmail(email)) {
      throw new EmailAlreadyExistsError(`Email ${email.value} is already registered`);
    }

    // Create domain objects
    const hashedPassword = await this.authService.hashPassword(password);
    const userId = UserId.generate();
    
    const user = new User(
      userId,
      email,
      hashedPassword,
      UserStatus.PENDING
    );

    // Persist user
    await this.userRepository.save(user);

    // Trigger side effects
    await this.authService.sendActivationEmail(user);

    // Return DTO
    return {
      id: user.id.value,
      email: user.email.value,
      status: user.status.value,
      createdAt: user.createdAt
    };
  }
}
```

#### **login-user-use-case.js**
```javascript
import { Email } from '../../domain/value-objects/email.js';
import { InvalidCredentialsError } from '../../../../shared/errors/domain-errors.js';

export class LoginUserUseCase {
  constructor(userRepository, authService, authenticationService) {
    this.userRepository = userRepository;
    this.authService = authService;
    this.authenticationService = authenticationService;
  }

  async execute(command) {
    const email = new Email(command.email);
    
    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      throw new InvalidCredentialsError('Invalid email or password');
    }

    const isValid = await this.authenticationService.authenticate(user, command.password);
    if (!isValid) {
      throw new InvalidCredentialsError('Invalid email or password');
    }

    const session = await this.authService.createSession(user);
    
    return {
      user: {
        id: user.id.value,
        email: user.email.value,
        status: user.status.value
      },
      session: {
        token: session.token,
        expiresAt: session.expiresAt
      }
    };
  }
}
```

### **📁 modules/identity/infrastructure/persistence/**

#### **user-repository.js**
```javascript
import { IUserRepository } from '../../application/ports/user-repository.js';
import { User } from '../../domain/entities/user.js';
import { UserId } from '../../domain/entities/user-id.js';
import { Email } from '../../domain/value-objects/email.js';
import { HashedPassword } from '../../domain/value-objects/password.js';
import { UserStatus } from '../../domain/value-objects/user-status.js';

export class UserRepository extends IUserRepository {
  constructor(storage = localStorage) {
    super();
    this.storage = storage;
    this.key = 'identity_users';
  }

  async save(user) {
    const users = this.#getAllUsers();
    const userData = this.#toPersistence(user);
    
    const existingIndex = users.findIndex(u => u.id === user.id.value);
    if (existingIndex >= 0) {
      users[existingIndex] = userData;
    } else {
      users.push(userData);
    }
    
    this.storage.setItem(this.key, JSON.stringify(users));
  }

  async findById(id) {
    const users = this.#getAllUsers();
    const userData = users.find(u => u.id === id.value);
    return userData ? this.#toDomain(userData) : null;
  }

  async findByEmail(email) {
    const users = this.#getAllUsers();
    const userData = users.find(u => u.email === email.value);
    return userData ? this.#toDomain(userData) : null;
  }

  async existsByEmail(email) {
    const users = this.#getAllUsers();
    return users.some(u => u.email === email.value);
  }

  async delete(id) {
    const users = this.#getAllUsers();
    const filteredUsers = users.filter(u => u.id !== id.value);
    this.storage.setItem(this.key, JSON.stringify(filteredUsers));
  }

  #getAllUsers() {
    const data = this.storage.getItem(this.key);
    return data ? JSON.parse(data) : [];
  }

  #toPersistence(user) {
    return {
      id: user.id.value,
      email: user.email.value,
      hashedPassword: user.hashedPassword.hash,
      salt: user.hashedPassword.salt,
      status: user.status.value,
      roles: user.roles,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString()
    };
  }

  #toDomain(userData) {
    const userId = new UserId(userData.id);
    const email = new Email(userData.email);
    const hashedPassword = new HashedPassword(userData.hashedPassword, userData.salt);
    const status = new UserStatus(userData.status);
    
    return new User(
      userId,
      email,
      hashedPassword,
      status,
      userData.roles || []
    );
  }
}
```

#### **auth-service.js**
```javascript
import { IAuthService } from '../../application/ports/auth-service.js';
import { HashedPassword } from '../../domain/value-objects/password.js';

export class AuthService extends IAuthService {
  async hashPassword(password) {
    // Simplified hashing - use a proper library like bcrypt in production
    const salt = Math.random().toString(36).substring(2, 15);
    const encoder = new TextEncoder();
    const data = encoder.encode(password.value + salt);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return new HashedPassword(hash, salt);
  }

  async verifyPassword(hashedPassword, plainPassword) {
    return hashedPassword.matches(plainPassword);
  }

  async createSession(user) {
    const token = `token_${Date.now()}_${Math.random().toString(36).substr(2)}`;
    const session = {
      userId: user.id.value,
      token: token,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      createdAt: new Date()
    };

    // Store session
    localStorage.setItem('auth_session', JSON.stringify(session));
    localStorage.setItem('auth_token', token);
    
    return session;
  }

  async sendActivationEmail(user) {
    // In a real app, this would call an email service
    console.log(`Sending activation email to: ${user.email.value}`);
    const activationToken = `activate_${Date.now()}_${Math.random().toString(36).substr(2)}`;
    
    // Store activation token temporarily
    localStorage.setItem(`activation_${user.id.value}`, activationToken);
    
    // Simulate email sending
    setTimeout(() => {
      console.log(`Activation link: http://localhost:3000/activate?token=${activationToken}&userId=${user.id.value}`);
    }, 1000);
  }
}
```

### **📁 modules/identity/presentation/**

#### **components/login-form.js**
```javascript
export class LoginForm {
  constructor(loginUseCase, onSuccess, onError) {
    this.loginUseCase = loginUseCase;
    this.onSuccess = onSuccess;
    this.onError = onError;
    this.isLoading = false;
  }

  render() {
    const container = document.createElement('div');
    container.className = 'login-form';
    
    container.innerHTML = `
      <form class="login-form__form">
        <h2>Login</h2>
        <div class="form-group">
          <label for="email">Email</label>
          <input type="email" id="email" name="email" required>
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required>
        </div>
        <button type="submit" ${this.isLoading ? 'disabled' : ''}>
          ${this.isLoading ? 'Logging in...' : 'Login'}
        </button>
        <div class="error-message" style="display: none;"></div>
      </form>
    `;

    this.form = container.querySelector('.login-form__form');
    this.errorDiv = container.querySelector('.error-message');
    
    this.#attachEvents();
    return container;
  }

  #attachEvents() {
    this.form.addEventListener('submit', async (e) => {
      e.preventDefault();
      await this.#handleSubmit();
    });
  }

  async #handleSubmit() {
    const formData = new FormData(this.form);
    const email = formData.get('email');
    const password = formData.get('password');

    try {
      this.#setLoading(true);
      this.#clearError();

      const result = await this.loginUseCase.execute({ email, password });
      
      this.#setLoading(false);
      this.onSuccess(result);
    } catch (error) {
      this.#setLoading(false);
      this.#showError(error.message);
      this.onError(error);
    }
  }

  #setLoading(loading) {
    this.isLoading = loading;
    const button = this.form.querySelector('button');
    button.disabled = loading;
    button.textContent = loading ? 'Logging in...' : 'Login';
  }

  #showError(message) {
    this.errorDiv.textContent = message;
    this.errorDiv.style.display = 'block';
  }

  #clearError() {
    this.errorDiv.textContent = '';
    this.errorDiv.style.display = 'none';
  }
}
```

#### **views/login-view.js**
```javascript
import { LoginForm } from '../components/login-form.js';

export class LoginView {
  constructor(loginUseCase, router) {
    this.loginUseCase = loginUseCase;
    this.router = router;
  }

  render() {
    const container = document.createElement('div');
    container.className = 'login-view';
    
    container.innerHTML = `
      <div class="login-view__header">
        <h1>Welcome Back</h1>
        <p>Please login to your account</p>
      </div>
      <div class="login-view__form-container"></div>
      <div class="login-view__footer">
        <p>Don't have an account? <a href="#" class="register-link">Register here</a></p>
      </div>
    `;

    const formContainer = container.querySelector('.login-view__form-container');
    const registerLink = container.querySelector('.register-link');

    const loginForm = new LoginForm(
      this.loginUseCase,
      (result) => this.#handleLoginSuccess(result),
      (error) => this.#handleLoginError(error)
    );

    formContainer.appendChild(loginForm.render());
    
    registerLink.addEventListener('click', (e) => {
      e.preventDefault();
      this.router.navigate('/register');
    });

    return container;
  }

  #handleLoginSuccess(result) {
    console.log('Login successful:', result);
    this.router.navigate('/dashboard');
  }

  #handleLoginError(error) {
    console.error('Login failed:', error);
  }
}
```

## 🚀 **Application Bootstrap**

### **📁 app.js**
```javascript
import { UserRepository } from './modules/identity/infrastructure/persistence/user-repository.js';
import { AuthService } from './modules/identity/infrastructure/persistence/auth-service.js';
import { AuthenticationService } from './modules/identity/domain/services/authentication-service.js';
import { RegisterUserUseCase } from './modules/identity/application/use-cases/register-user-use-case.js';
import { LoginUserUseCase } from './modules/identity/application/use-cases/login-user-use-case.js';
import { LoginView } from './modules/identity/presentation/views/login-view.js';

// Simple router
class Router {
  constructor() {
    this.routes = {};
    this.currentView = null;
  }

  addRoute(path, viewFactory) {
    this.routes[path] = viewFactory;
  }

  navigate(path) {
    const viewFactory = this.routes[path];
    if (viewFactory && this.currentView) {
      this.currentView.innerHTML = '';
      const view = viewFactory();
      this.currentView.appendChild(view.render());
    }
  }
}

// Dependency Injection Container
class Container {
  constructor() {
    this.services = {};
  }

  register(name, factory) {
    this.services[name] = factory;
  }

  get(name) {
    if (!this.services[name]) {
      throw new Error(`Service ${name} not found`);
    }
    return this.services[name](this);
  }
}

// Setup application
class Application {
  constructor() {
    this.container = new Container();
    this.router = new Router();
    this.#setupContainer();
    this.#setupRoutes();
  }

  #setupContainer() {
    this.container.register('userRepository', () => new UserRepository());
    this.container.register('authService', () => new AuthService());
    this.container.register('authenticationService', () => new AuthenticationService());
    
    this.container.register('registerUserUseCase', (container) => 
      new RegisterUserUseCase(
        container.get('userRepository'),
        container.get('authService')
      )
    );
    
    this.container.register('loginUserUseCase', (container) => 
      new LoginUserUseCase(
        container.get('userRepository'),
        container.get('authService'),
        container.get('authenticationService')
      )
    );
  }

  #setupRoutes() {
    this.router.addRoute('/login', () => 
      new LoginView(
        this.container.get('loginUserUseCase'),
        this.router
      )
    );
  }

  start(containerElement) {
    this.router.currentView = containerElement;
    this.router.navigate('/login');
  }
}

// Start the app
const app = new Application();
app.start(document.getElementById('app'));
```

## 📦 **HTML Entry Point**

### **index.html**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDD JavaScript App</title>
    <style>
        .login-view {
            max-width: 400px;
            margin: 50px auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        button {
            width: 100%;
            padding: 10px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:disabled {
            background: #6c757d;
            cursor: not-allowed;
        }
        .error-message {
            color: #dc3545;
            margin-top: 10px;
            padding: 10px;
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div id="app"></div>
    <script type="module" src="app.js"></script>
</body>
</html>
```

## 🎯 **Key Implementation Notes**

1. **Pure JavaScript**: Uses ES6+ classes and modules
2. **No Frameworks**: Can work with any frontend framework or vanilla JS
3. **Separation of Concerns**: Clear boundaries between layers
4. **Testability**: Easy to mock dependencies for unit testing
5. **Domain Focus**: Business logic is isolated and framework-agnostic

This implementation provides a solid foundation for a DDD-based JavaScript application that can scale and maintain clean architecture principles!

Here's the complete implementation of the Catalog module in pure JavaScript following the same DDD structure:

## 🏗️ **Catalog Module Structure**

```
modules/
└── catalog/
    ├── domain/
    │   ├── entities/
    │   ├── value-objects/
    │   └── services/
    ├── application/
    │   ├── use-cases/
    │   └── ports/
    ├── infrastructure/
    │   └── persistence/
    └── presentation/
        ├── components/
        └── views/
```

## 📦 **Catalog Domain Implementation**

### **📁 modules/catalog/domain/value-objects/**

#### **price.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';
import { DomainError } from '../../../../shared/errors/domain-errors.js';

export class InvalidPriceError extends DomainError {}

export class Price extends ValueObject {
  constructor(amount, currency = 'USD') {
    super();
    this.amount = Number(amount);
    this.currency = currency.toUpperCase();
    this.#validate();
  }

  #validate() {
    if (this.amount < 0) {
      throw new InvalidPriceError('Price cannot be negative');
    }
    if (isNaN(this.amount)) {
      throw new InvalidPriceError('Price amount must be a valid number');
    }
    if (!['USD', 'EUR', 'GBP'].includes(this.currency)) {
      throw new InvalidPriceError(`Unsupported currency: ${this.currency}`);
    }
  }

  add(other) {
    if (this.currency !== other.currency) {
      throw new InvalidPriceError('Cannot add prices with different currencies');
    }
    return new Price(this.amount + other.amount, this.currency);
  }

  subtract(other) {
    if (this.currency !== other.currency) {
      throw new InvalidPriceError('Cannot subtract prices with different currencies');
    }
    return new Price(this.amount - other.amount, this.currency);
  }

  multiply(factor) {
    return new Price(this.amount * factor, this.currency);
  }

  format() {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: this.currency
    }).format(this.amount);
  }

  isGreaterThan(other) {
    return this.amount > other.amount;
  }

  isLessThan(other) {
    return this.amount < other.amount;
  }
}
```

#### **sku.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';
import { DomainError } from '../../../../shared/errors/domain-errors.js';

export class InvalidSKUError extends DomainError {}

export class SKU extends ValueObject {
  constructor(value) {
    super();
    this.value = value.toUpperCase().trim();
    this.#validate();
  }

  #validate() {
    const skuRegex = /^[A-Z0-9]{3,10}-[A-Z0-9]{3,10}$/;
    if (!skuRegex.test(this.value)) {
      throw new InvalidSKUError(
        'SKU must be in format: ABC-123 (3-10 chars, hyphen, 3-10 chars)'
      );
    }
  }

  getPrefix() {
    return this.value.split('-')[0];
  }

  getSuffix() {
    return this.value.split('-')[1];
  }

  toString() {
    return this.value;
  }
}
```

#### **product-status.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';

export class ProductStatus extends ValueObject {
  static DRAFT = new ProductStatus('draft');
  static ACTIVE = new ProductStatus('active');
  static INACTIVE = new ProductStatus('inactive');
  static DISCONTINUED = new ProductStatus('discontinued');
  static OUT_OF_STOCK = new ProductStatus('out_of_stock');

  constructor(value) {
    super();
    this.value = value;
  }

  canBePurchased() {
    return this.value === ProductStatus.ACTIVE.value;
  }

  canBeEdited() {
    return [
      ProductStatus.DRAFT.value,
      ProductStatus.ACTIVE.value,
      ProductStatus.INACTIVE.value
    ].includes(this.value);
  }

  toString() {
    return this.value;
  }
}
```

### **📁 modules/catalog/domain/entities/**

#### **category-id.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';

export class CategoryId extends ValueObject {
  constructor(value) {
    super();
    this.value = value;
  }

  static generate() {
    return new CategoryId(`cat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`);
  }

  toString() {
    return this.value;
  }
}
```

#### **product-id.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';

export class ProductId extends ValueObject {
  constructor(value) {
    super();
    this.value = value;
  }

  static generate() {
    return new ProductId(`prod_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`);
  }

  toString() {
    return this.value;
  }
}
```

#### **category.js**
```javascript
import { Entity } from './entity.js';
import { CategoryId } from './category-id.js';

export class Category extends Entity {
  constructor(id, name, description = '', parentId = null) {
    super(id);
    this.name = name;
    this.description = description;
    this.parentId = parentId;
    this.children = [];
    this.isActive = true;
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  addChild(category) {
    if (category.parentId && category.parentId !== this.id) {
      throw new Error('Category already has a different parent');
    }
    category.parentId = this.id;
    this.children.push(category);
    this.updatedAt = new Date();
  }

  removeChild(categoryId) {
    this.children = this.children.filter(child => !child.id.equals(categoryId));
    this.updatedAt = new Date();
  }

  deactivate() {
    this.isActive = false;
    this.updatedAt = new Date();
    // Deactivate all children recursively
    this.children.forEach(child => child.deactivate());
  }

  activate() {
    this.isActive = true;
    this.updatedAt = new Date();
  }

  getPath() {
    const path = [this.name];
    return path.join(' > ');
  }
}
```

#### **product.js**
```javascript
import { Entity } from './entity.js';
import { ProductId } from './product-id.js';
import { SKU } from '../value-objects/sku.js';
import { Price } from '../value-objects/price.js';
import { ProductStatus } from '../value-objects/product-status.js';

export class Product extends Entity {
  constructor(
    id,
    sku,
    name,
    description,
    price,
    categoryId,
    status = ProductStatus.DRAFT
  ) {
    super(id);
    this.sku = sku;
    this.name = name;
    this.description = description;
    this.price = price;
    this.categoryId = categoryId;
    this.status = status;
    this.images = [];
    this.tags = [];
    this.inventory = null;
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  updateDetails({ name, description, price }) {
    if (!this.status.canBeEdited()) {
      throw new Error(`Cannot edit product with status: ${this.status}`);
    }

    this.name = name || this.name;
    this.description = description || this.description;
    this.price = price || this.price;
    this.updatedAt = new Date();

    this.addDomainEvent({
      type: 'PRODUCT_UPDATED',
      productId: this.id,
      updatedFields: { name, description, price }
    });
  }

  activate() {
    this.status = ProductStatus.ACTIVE;
    this.updatedAt = new Date();
    this.addDomainEvent({
      type: 'PRODUCT_ACTIVATED',
      productId: this.id
    });
  }

  deactivate() {
    this.status = ProductStatus.INACTIVE;
    this.updatedAt = new Date();
    this.addDomainEvent({
      type: 'PRODUCT_DEACTIVATED',
      productId: this.id
    });
  }

  discontinue() {
    this.status = ProductStatus.DISCONTINUED;
    this.updatedAt = new Date();
    this.addDomainEvent({
      type: 'PRODUCT_DISCONTINUED',
      productId: this.id
    });
  }

  addImage(imageUrl, altText = '') {
    this.images.push({ url: imageUrl, alt: altText });
    this.updatedAt = new Date();
  }

  removeImage(imageUrl) {
    this.images = this.images.filter(img => img.url !== imageUrl);
    this.updatedAt = new Date();
  }

  addTag(tag) {
    if (!this.tags.includes(tag)) {
      this.tags.push(tag);
      this.updatedAt = new Date();
    }
  }

  removeTag(tag) {
    this.tags = this.tags.filter(t => t !== tag);
    this.updatedAt = new Date();
  }

  setInventory(inventory) {
    this.inventory = inventory;
    this.updatedAt = new Date();
  }

  isAvailable() {
    return this.status.canBePurchased() && 
           this.inventory && 
           this.inventory.isInStock();
  }

  canBePurchased(quantity = 1) {
    return this.isAvailable() && this.inventory.hasSufficientStock(quantity);
  }
}
```

#### **inventory.js**
```javascript
import { Entity } from './entity.js';
import { ProductId } from './product-id.js';

export class Inventory extends Entity {
  constructor(id, productId, quantity = 0, lowStockThreshold = 10) {
    super(id);
    this.productId = productId;
    this.quantity = quantity;
    this.lowStockThreshold = lowStockThreshold;
    this.reserved = 0;
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  increaseStock(amount) {
    if (amount <= 0) {
      throw new Error('Stock increase amount must be positive');
    }
    this.quantity += amount;
    this.updatedAt = new Date();
    
    this.addDomainEvent({
      type: 'STOCK_INCREASED',
      productId: this.productId,
      amount,
      newQuantity: this.quantity
    });
  }

  decreaseStock(amount) {
    if (amount <= 0) {
      throw new Error('Stock decrease amount must be positive');
    }
    if (this.availableQuantity < amount) {
      throw new Error('Insufficient stock available');
    }
    
    this.quantity -= amount;
    this.updatedAt = new Date();
    
    this.addDomainEvent({
      type: 'STOCK_DECREASED',
      productId: this.productId,
      amount,
      newQuantity: this.quantity
    });
  }

  reserve(amount) {
    if (amount <= 0) {
      throw new Error('Reservation amount must be positive');
    }
    if (this.availableQuantity < amount) {
      throw new Error('Insufficient stock available for reservation');
    }
    
    this.reserved += amount;
    this.updatedAt = new Date();
    
    this.addDomainEvent({
      type: 'STOCK_RESERVED',
      productId: this.productId,
      amount,
      reserved: this.reserved
    });
  }

  releaseReservation(amount) {
    if (amount <= 0) {
      throw new Error('Release amount must be positive');
    }
    if (this.reserved < amount) {
      throw new Error('Cannot release more than reserved amount');
    }
    
    this.reserved -= amount;
    this.updatedAt = new Date();
  }

  get availableQuantity() {
    return this.quantity - this.reserved;
  }

  isInStock() {
    return this.availableQuantity > 0;
  }

  hasSufficientStock(quantity) {
    return this.availableQuantity >= quantity;
  }

  isLowStock() {
    return this.availableQuantity <= this.lowStockThreshold;
  }

  updateLowStockThreshold(threshold) {
    this.lowStockThreshold = threshold;
    this.updatedAt = new Date();
  }
}
```

### **📁 modules/catalog/domain/services/**

#### **product-service.js**
```javascript
export class ProductService {
  generateSKU(productName, category) {
    const prefix = category.name.substring(0, 3).toUpperCase();
    const randomSuffix = Math.random().toString(36).substring(2, 6).toUpperCase();
    const skuValue = `${prefix}-${randomSuffix}`;
    
    return skuValue;
  }

  calculateDiscountPrice(originalPrice, discountPercentage) {
    if (discountPercentage < 0 || discountPercentage > 100) {
      throw new Error('Discount percentage must be between 0 and 100');
    }
    
    const discountAmount = originalPrice.amount * (discountPercentage / 100);
    return originalPrice.subtract(new Price(discountAmount, originalPrice.currency));
  }

  validateProductForActivation(product) {
    const errors = [];
    
    if (!product.name || product.name.trim().length === 0) {
      errors.push('Product name is required');
    }
    
    if (!product.description || product.description.trim().length === 0) {
      errors.push('Product description is required');
    }
    
    if (product.price.amount <= 0) {
      errors.push('Product price must be greater than 0');
    }
    
    if (!product.categoryId) {
      errors.push('Product category is required');
    }
    
    if (product.images.length === 0) {
      errors.push('At least one product image is required');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }
}
```

#### **inventory-service.js**
```javascript
export class InventoryService {
  calculateReorderPoint(historicalSales, leadTimeDays, safetyStock = 0) {
    const averageDailySales = historicalSales.reduce((sum, sales) => sum + sales, 0) / historicalSales.length;
    const leadTimeDemand = averageDailySales * leadTimeDays;
    return Math.ceil(leadTimeDemand + safetyStock);
  }

  shouldReorder(inventory, historicalSales, leadTimeDays) {
    const reorderPoint = this.calculateReorderPoint(historicalSales, leadTimeDays);
    return inventory.availableQuantity <= reorderPoint;
  }

  calculateOptimalOrderQuantity(inventory, demand, holdingCost, orderingCost) {
    if (demand <= 0 || holdingCost <= 0 || orderingCost <= 0) {
      throw new Error('Demand, holding cost, and ordering cost must be positive');
    }
    
    // Economic Order Quantity formula
    const eoq = Math.sqrt((2 * demand * orderingCost) / holdingCost);
    return Math.ceil(eoq);
  }

  transferStock(fromInventory, toInventory, amount, reason = 'transfer') {
    if (!fromInventory.hasSufficientStock(amount)) {
      throw new Error('Insufficient stock for transfer');
    }
    
    fromInventory.decreaseStock(amount);
    toInventory.increaseStock(amount);
    
    return {
      fromInventory,
      toInventory,
      amount,
      reason,
      timestamp: new Date()
    };
  }
}
```

## 🚀 **Catalog Application Layer**

### **📁 modules/catalog/application/ports/**

#### **product-repository.js**
```javascript
export class IProductRepository {
  async save(product) {
    throw new Error('Method not implemented');
  }

  async findById(id) {
    throw new Error('Method not implemented');
  }

  async findBySKU(sku) {
    throw new Error('Method not implemented');
  }

  async findByCategory(categoryId) {
    throw new Error('Method not implemented');
  }

  async search(criteria) {
    throw new Error('Method not implemented');
  }

  async delete(id) {
    throw new Error('Method not implemented');
  }

  async existsWithSKU(sku) {
    throw new Error('Method not implemented');
  }
}
```

#### **category-repository.js**
```javascript
export class ICategoryRepository {
  async save(category) {
    throw new Error('Method not implemented');
  }

  async findById(id) {
    throw new Error('Method not implemented');
  }

  async findByName(name) {
    throw new Error('Method not implemented');
  }

  async findRootCategories() {
    throw new Error('Method not implemented');
  }

  async findChildren(parentId) {
    throw new Error('Method not implemented');
  }

  async delete(id) {
    throw new Error('Method not implemented');
  }
}
```

#### **inventory-repository.js**
```javascript
export class IInventoryRepository {
  async save(inventory) {
    throw new Error('Method not implemented');
  }

  async findByProductId(productId) {
    throw new Error('Method not implemented');
  }

  async findLowStock(threshold) {
    throw new Error('Method not implemented');
  }

  async updateStock(productId, quantity) {
    throw new Error('Method not implemented');
  }
}
```

### **📁 modules/catalog/application/use-cases/**

#### **create-product-use-case.js**
```javascript
import { Product } from '../../domain/entities/product.js';
import { ProductId } from '../../domain/entities/product-id.js';
import { SKU } from '../../domain/value-objects/sku.js';
import { Price } from '../../domain/value-objects/price.js';
import { ProductStatus } from '../../domain/value-objects/product-status.js';
import { ProductService } from '../../domain/services/product-service.js';

export class CreateProductUseCase {
  constructor(productRepository, categoryRepository, inventoryRepository) {
    this.productRepository = productRepository;
    this.categoryRepository = categoryRepository;
    this.inventoryRepository = inventoryRepository;
    this.productService = new ProductService();
  }

  async execute(command) {
    // Validate category exists
    const category = await this.categoryRepository.findById(command.categoryId);
    if (!category) {
      throw new Error(`Category not found: ${command.categoryId}`);
    }

    // Generate or validate SKU
    let sku;
    if (command.sku) {
      sku = new SKU(command.sku);
      
      // Check if SKU already exists
      if (await this.productRepository.existsWithSKU(sku)) {
        throw new Error(`Product with SKU ${sku.value} already exists`);
      }
    } else {
      const skuValue = this.productService.generateSKU(command.name, category);
      sku = new SKU(skuValue);
    }

    // Create price object
    const price = new Price(command.price, command.currency);

    // Create product
    const productId = ProductId.generate();
    const product = new Product(
      productId,
      sku,
      command.name,
      command.description,
      price,
      command.categoryId,
      command.status ? new ProductStatus(command.status) : ProductStatus.DRAFT
    );

    // Add images if provided
    if (command.images) {
      command.images.forEach(image => product.addImage(image.url, image.alt));
    }

    // Add tags if provided
    if (command.tags) {
      command.tags.forEach(tag => product.addTag(tag));
    }

    // Save product
    await this.productRepository.save(product);

    // Create inventory if initial quantity provided
    if (command.initialQuantity > 0) {
      const inventoryId = `inv_${productId.value}`;
      const inventory = new Inventory(inventoryId, productId, command.initialQuantity);
      await this.inventoryRepository.save(inventory);
      product.setInventory(inventory);
    }

    return {
      id: product.id.value,
      sku: product.sku.value,
      name: product.name,
      description: product.description,
      price: product.price.amount,
      currency: product.price.currency,
      status: product.status.value,
      categoryId: product.categoryId.value,
      images: product.images,
      tags: product.tags,
      createdAt: product.createdAt
    };
  }
}
```

#### **update-product-use-case.js**
```javascript
import { Price } from '../../domain/value-objects/price.js';

export class UpdateProductUseCase {
  constructor(productRepository) {
    this.productRepository = productRepository;
  }

  async execute(command) {
    const product = await this.productRepository.findById(command.productId);
    if (!product) {
      throw new Error(`Product not found: ${command.productId}`);
    }

    const updates = {};

    if (command.name !== undefined) {
      updates.name = command.name;
    }

    if (command.description !== undefined) {
      updates.description = command.description;
    }

    if (command.price !== undefined) {
      updates.price = new Price(command.price, command.currency || 'USD');
    }

    product.updateDetails(updates);

    await this.productRepository.save(product);

    return {
      id: product.id.value,
      name: product.name,
      description: product.description,
      price: product.price.amount,
      currency: product.price.currency,
      status: product.status.value,
      updatedAt: product.updatedAt
    };
  }
}
```

#### **search-products-use-case.js**
```javascript
export class SearchProductsUseCase {
  constructor(productRepository) {
    this.productRepository = productRepository;
  }

  async execute(criteria) {
    const searchCriteria = this.#buildSearchCriteria(criteria);
    const products = await this.productRepository.search(searchCriteria);

    return products.map(product => ({
      id: product.id.value,
      sku: product.sku.value,
      name: product.name,
      description: product.description,
      price: product.price.amount,
      currency: product.price.currency,
      status: product.status.value,
      categoryId: product.categoryId.value,
      images: product.images,
      tags: product.tags,
      isAvailable: product.isAvailable(),
      inventory: product.inventory ? {
        quantity: product.inventory.quantity,
        available: product.inventory.availableQuantity,
        reserved: product.inventory.reserved,
        isLowStock: product.inventory.isLowStock()
      } : null
    }));
  }

  #buildSearchCriteria(criteria) {
    const searchCriteria = {
      query: criteria.query,
      categoryId: criteria.categoryId,
      status: criteria.status,
      minPrice: criteria.minPrice,
      maxPrice: criteria.maxPrice,
      tags: criteria.tags,
      inStock: criteria.inStock,
      page: criteria.page || 1,
      limit: criteria.limit || 20,
      sortBy: criteria.sortBy || 'name',
      sortOrder: criteria.sortOrder || 'asc'
    };

    // Remove undefined values
    return Object.fromEntries(
      Object.entries(searchCriteria).filter(([_, value]) => value !== undefined)
    );
  }
}
```

## 💾 **Catalog Infrastructure**

### **📁 modules/catalog/infrastructure/persistence/**

#### **product-repository.js**
```javascript
import { IProductRepository } from '../../application/ports/product-repository.js';
import { Product } from '../../domain/entities/product.js';
import { ProductId } from '../../domain/entities/product-id.js';
import { SKU } from '../../domain/value-objects/sku.js';
import { Price } from '../../domain/value-objects/price.js';
import { ProductStatus } from '../../domain/value-objects/product-status.js';

export class ProductRepository extends IProductRepository {
  constructor(storage = localStorage) {
    super();
    this.storage = storage;
    this.key = 'catalog_products';
  }

  async save(product) {
    const products = this.#getAllProducts();
    const productData = this.#toPersistence(product);
    
    const existingIndex = products.findIndex(p => p.id === product.id.value);
    if (existingIndex >= 0) {
      products[existingIndex] = productData;
    } else {
      products.push(productData);
    }
    
    this.storage.setItem(this.key, JSON.stringify(products));
  }

  async findById(id) {
    const products = this.#getAllProducts();
    const productData = products.find(p => p.id === id.value);
    return productData ? this.#toDomain(productData) : null;
  }

  async findBySKU(sku) {
    const products = this.#getAllProducts();
    const productData = products.find(p => p.sku === sku.value);
    return productData ? this.#toDomain(productData) : null;
  }

  async findByCategory(categoryId) {
    const products = this.#getAllProducts();
    const productData = products.filter(p => p.categoryId === categoryId.value);
    return productData.map(data => this.#toDomain(data));
  }

  async search(criteria) {
    let products = this.#getAllProducts().map(data => this.#toDomain(data));

    // Apply filters
    if (criteria.query) {
      const query = criteria.query.toLowerCase();
      products = products.filter(p => 
        p.name.toLowerCase().includes(query) ||
        p.description.toLowerCase().includes(query) ||
        p.sku.value.toLowerCase().includes(query)
      );
    }

    if (criteria.categoryId) {
      products = products.filter(p => p.categoryId.value === criteria.categoryId);
    }

    if (criteria.status) {
      products = products.filter(p => p.status.value === criteria.status);
    }

    if (criteria.minPrice !== undefined) {
      products = products.filter(p => p.price.amount >= criteria.minPrice);
    }

    if (criteria.maxPrice !== undefined) {
      products = products.filter(p => p.price.amount <= criteria.maxPrice);
    }

    if (criteria.tags && criteria.tags.length > 0) {
      products = products.filter(p => 
        criteria.tags.some(tag => p.tags.includes(tag))
      );
    }

    if (criteria.inStock) {
      products = products.filter(p => p.isAvailable());
    }

    // Apply sorting
    if (criteria.sortBy) {
      products.sort((a, b) => {
        let aValue, bValue;
        
        switch (criteria.sortBy) {
          case 'name':
            aValue = a.name;
            bValue = b.name;
            break;
          case 'price':
            aValue = a.price.amount;
            bValue = b.price.amount;
            break;
          case 'createdAt':
            aValue = a.createdAt;
            bValue = b.createdAt;
            break;
          default:
            aValue = a.name;
            bValue = b.name;
        }

        if (aValue < bValue) return criteria.sortOrder === 'asc' ? -1 : 1;
        if (aValue > bValue) return criteria.sortOrder === 'asc' ? 1 : -1;
        return 0;
      });
    }

    // Apply pagination
    const page = criteria.page || 1;
    const limit = criteria.limit || 20;
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;

    return products.slice(startIndex, endIndex);
  }

  async delete(id) {
    const products = this.#getAllProducts();
    const filteredProducts = products.filter(p => p.id !== id.value);
    this.storage.setItem(this.key, JSON.stringify(filteredProducts));
  }

  async existsWithSKU(sku) {
    const products = this.#getAllProducts();
    return products.some(p => p.sku === sku.value);
  }

  #getAllProducts() {
    const data = this.storage.getItem(this.key);
    return data ? JSON.parse(data) : [];
  }

  #toPersistence(product) {
    return {
      id: product.id.value,
      sku: product.sku.value,
      name: product.name,
      description: product.description,
      price: product.price.amount,
      currency: product.price.currency,
      categoryId: product.categoryId.value,
      status: product.status.value,
      images: product.images,
      tags: product.tags,
      createdAt: product.createdAt.toISOString(),
      updatedAt: product.updatedAt.toISOString()
    };
  }

  #toDomain(productData) {
    const productId = new ProductId(productData.id);
    const sku = new SKU(productData.sku);
    const price = new Price(productData.price, productData.currency);
    const status = new ProductStatus(productData.status);
    const categoryId = new CategoryId(productData.categoryId);

    const product = new Product(
      productId,
      sku,
      productData.name,
      productData.description,
      price,
      categoryId,
      status
    );

    productData.images.forEach(image => 
      product.addImage(image.url, image.alt)
    );
    productData.tags.forEach(tag => product.addTag(tag));

    return product;
  }
}
```

#### **category-repository.js**
```javascript
import { ICategoryRepository } from '../../application/ports/category-repository.js';
import { Category } from '../../domain/entities/category.js';
import { CategoryId } from '../../domain/entities/category-id.js';

export class CategoryRepository extends ICategoryRepository {
  constructor(storage = localStorage) {
    super();
    this.storage = storage;
    this.key = 'catalog_categories';
  }

  async save(category) {
    const categories = this.#getAllCategories();
    const categoryData = this.#toPersistence(category);
    
    const existingIndex = categories.findIndex(c => c.id === category.id.value);
    if (existingIndex >= 0) {
      categories[existingIndex] = categoryData;
    } else {
      categories.push(categoryData);
    }
    
    this.storage.setItem(this.key, JSON.stringify(categories));
  }

  async findById(id) {
    const categories = this.#getAllCategories();
    const categoryData = categories.find(c => c.id === id.value);
    return categoryData ? this.#toDomain(categoryData) : null;
  }

  async findByName(name) {
    const categories = this.#getAllCategories();
    const categoryData = categories.find(c => c.name.toLowerCase() === name.toLowerCase());
    return categoryData ? this.#toDomain(categoryData) : null;
  }

  async findRootCategories() {
    const categories = this.#getAllCategories();
    const rootCategoriesData = categories.filter(c => !c.parentId);
    return rootCategoriesData.map(data => this.#toDomain(data));
  }

  async findChildren(parentId) {
    const categories = this.#getAllCategories();
    const childrenData = categories.filter(c => c.parentId === parentId.value);
    return childrenData.map(data => this.#toDomain(data));
  }

  async delete(id) {
    const categories = this.#getAllCategories();
    const filteredCategories = categories.filter(c => c.id !== id.value);
    this.storage.setItem(this.key, JSON.stringify(filteredCategories));
  }

  #getAllCategories() {
    const data = this.storage.getItem(this.key);
    return data ? JSON.parse(data) : [];
  }

  #toPersistence(category) {
    return {
      id: category.id.value,
      name: category.name,
      description: category.description,
      parentId: category.parentId ? category.parentId.value : null,
      isActive: category.isActive,
      createdAt: category.createdAt.toISOString(),
      updatedAt: category.updatedAt.toISOString()
    };
  }

  #toDomain(categoryData) {
    const categoryId = new CategoryId(categoryData.id);
    const parentId = categoryData.parentId ? new CategoryId(categoryData.parentId) : null;

    const category = new Category(
      categoryId,
      categoryData.name,
      categoryData.description,
      parentId
    );

    category.isActive = categoryData.isActive;
    return category;
  }
}
```

## 🎨 **Catalog Presentation Layer**

### **📁 modules/catalog/presentation/components/**

Here's the complete Vue.js 2 implementation of the Catalog module:

## 🏗️ **Catalog Module Structure for Vue 2**

```
modules/
└── catalog/
    ├── domain/           (Same as before)
    ├── application/      (Same as before)
    ├── infrastructure/   (Same as before)
    └── presentation/
        ├── components/
        │   ├── ProductCard.vue
        │   ├── ProductList.vue
        │   └── ProductFilter.vue
        └── views/
            ├── ProductListView.vue
            └── ProductDetailView.vue
```

## 📦 **Vue 2 Presentation Layer**

### **📁 modules/catalog/presentation/components/ProductCard.vue**

```vue
<template>
  <div class="product-card" :class="{ 'product-card--out-of-stock': !product.isAvailable }">
    <div class="product-card__image">
      <img 
        :src="product.images[0]?.url || '/placeholder.jpg'" 
        :alt="product.images[0]?.alt || product.name"
        loading="lazy"
      >
      <span v-if="!product.isAvailable" class="out-of-stock-badge">
        Out of Stock
      </span>
    </div>
    
    <div class="product-card__content">
      <h3 class="product-card__title">{{ product.name }}</h3>
      <p class="product-card__description">
        {{ truncatedDescription }}
      </p>
      <div class="product-card__price">{{ formattedPrice }}</div>
      <div class="product-card__sku">SKU: {{ product.sku }}</div>
      
      <div class="product-card__actions">
        <button 
          class="btn btn--secondary" 
          @click="onViewDetails"
        >
          View Details
        </button>
        <button 
          class="btn btn--primary" 
          @click="onAddToCart"
          :disabled="!product.isAvailable"
        >
          {{ product.isAvailable ? 'Add to Cart' : 'Out of Stock' }}
        </button>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'ProductCard',
  props: {
    product: {
      type: Object,
      required: true
    }
  },
  computed: {
    truncatedDescription() {
      return this.product.description.length > 100 
        ? this.product.description.substring(0, 100) + '...'
        : this.product.description;
    },
    formattedPrice() {
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: this.product.currency || 'USD'
      }).format(this.product.price);
    }
  },
  methods: {
    onViewDetails() {
      this.$emit('view-details', this.product);
    },
    onAddToCart() {
      this.$emit('add-to-cart', this.product);
    }
  }
}
</script>

<style scoped>
.product-card {
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  overflow: hidden;
  transition: all 0.3s ease;
  background: white;
}

.product-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  transform: translateY(-2px);
}

.product-card--out-of-stock {
  opacity: 0.7;
}

.product-card__image {
  position: relative;
  height: 200px;
  overflow: hidden;
}

.product-card__image img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.out-of-stock-badge {
  position: absolute;
  top: 8px;
  right: 8px;
  background: #ff4444;
  color: white;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: bold;
}

.product-card__content {
  padding: 16px;
}

.product-card__title {
  margin: 0 0 8px 0;
  font-size: 18px;
  font-weight: 600;
  color: #333;
}

.product-card__description {
  margin: 0 0 12px 0;
  color: #666;
  font-size: 14px;
  line-height: 1.4;
}

.product-card__price {
  font-size: 20px;
  font-weight: bold;
  color: #2c5aa0;
  margin-bottom: 8px;
}

.product-card__sku {
  font-size: 12px;
  color: #888;
  margin-bottom: 16px;
}

.product-card__actions {
  display: flex;
  gap: 8px;
}

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s ease;
  flex: 1;
}

.btn--primary {
  background: #2c5aa0;
  color: white;
}

.btn--primary:hover:not(:disabled) {
  background: #1e3d6f;
}

.btn--primary:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.btn--secondary {
  background: #f5f5f5;
  color: #333;
  border: 1px solid #ddd;
}

.btn--secondary:hover {
  background: #e0e0e0;
}
</style>
```

### **📁 modules/catalog/presentation/components/ProductList.vue**

```vue
<template>
  <div class="product-list">
    <div v-if="loading" class="product-list__loading">
      <div class="loading-spinner"></div>
      <p>Loading products...</p>
    </div>
    
    <div v-else-if="products.length === 0" class="product-list__empty">
      <h3>No products found</h3>
      <p>Try adjusting your search criteria</p>
    </div>
    
    <div v-else class="product-list__grid">
      <ProductCard
        v-for="product in products"
        :key="product.id"
        :product="product"
        @view-details="$emit('view-details', $event)"
        @add-to-cart="$emit('add-to-cart', $event)"
        class="product-list__item"
      />
    </div>
    
    <div v-if="showPagination" class="product-list__pagination">
      <button 
        :disabled="currentPage === 1" 
        @click="changePage(currentPage - 1)"
        class="pagination-btn"
      >
        Previous
      </button>
      
      <span class="pagination-info">
        Page {{ currentPage }} of {{ totalPages }}
      </span>
      
      <button 
        :disabled="currentPage === totalPages" 
        @click="changePage(currentPage + 1)"
        class="pagination-btn"
      >
        Next
      </button>
    </div>
  </div>
</template>

<script>
import ProductCard from './ProductCard.vue'

export default {
  name: 'ProductList',
  components: {
    ProductCard
  },
  props: {
    products: {
      type: Array,
      default: () => []
    },
    loading: {
      type: Boolean,
      default: false
    },
    pagination: {
      type: Object,
      default: null
    }
  },
  computed: {
    showPagination() {
      return this.pagination && this.pagination.totalPages > 1;
    },
    currentPage() {
      return this.pagination ? this.pagination.currentPage : 1;
    },
    totalPages() {
      return this.pagination ? this.pagination.totalPages : 1;
    }
  },
  methods: {
    changePage(page) {
      this.$emit('page-change', page);
    }
  }
}
</script>

<style scoped>
.product-list__grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 20px;
  padding: 20px 0;
}

.product-list__loading {
  text-align: center;
  padding: 40px;
  color: #666;
}

.loading-spinner {
  border: 3px solid #f3f3f3;
  border-top: 3px solid #2c5aa0;
  border-radius: 50%;
  width: 40px;
  height: 40px;
  animation: spin 1s linear infinite;
  margin: 0 auto 16px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.product-list__empty {
  text-align: center;
  padding: 40px;
  color: #666;
}

.product-list__pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 16px;
  margin-top: 32px;
  padding: 20px 0;
  border-top: 1px solid #e0e0e0;
}

.pagination-btn {
  padding: 8px 16px;
  border: 1px solid #ddd;
  background: white;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.pagination-btn:hover:not(:disabled) {
  background: #f5f5f5;
}

.pagination-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.pagination-info {
  color: #666;
  font-size: 14px;
}
</style>
```

### **📁 modules/catalog/presentation/components/ProductFilter.vue**

```vue
<template>
  <div class="product-filter">
    <div class="product-filter__header">
      <h3>Filters</h3>
      <button v-if="hasActiveFilters" @click="clearFilters" class="clear-filters-btn">
        Clear All
      </button>
    </div>
    
    <div class="product-filter__content">
      <!-- Search -->
      <div class="filter-group">
        <label for="search-query" class="filter-label">Search</label>
        <input
          id="search-query"
          v-model="filters.query"
          type="text"
          placeholder="Search products..."
          class="filter-input"
          @input="onFilterChange"
        >
      </div>
      
      <!-- Category -->
      <div class="filter-group">
        <label for="category-filter" class="filter-label">Category</label>
        <select
          id="category-filter"
          v-model="filters.categoryId"
          class="filter-select"
          @change="onFilterChange"
        >
          <option value="">All Categories</option>
          <option
            v-for="category in categories"
            :key="category.id"
            :value="category.id"
          >
            {{ category.name }}
          </option>
        </select>
      </div>
      
      <!-- Price Range -->
      <div class="filter-group">
        <label class="filter-label">Price Range</label>
        <div class="price-range">
          <input
            v-model="filters.minPrice"
            type="number"
            placeholder="Min"
            class="filter-input price-input"
            @input="onFilterChange"
          >
          <span class="price-range-separator">to</span>
          <input
            v-model="filters.maxPrice"
            type="number"
            placeholder="Max"
            class="filter-input price-input"
            @input="onFilterChange"
          >
        </div>
      </div>
      
      <!-- In Stock Toggle -->
      <div class="filter-group">
        <label class="filter-checkbox">
          <input
            v-model="filters.inStock"
            type="checkbox"
            @change="onFilterChange"
          >
          <span class="checkmark"></span>
          In Stock Only
        </label>
      </div>
      
      <!-- Sort Options -->
      <div class="filter-group">
        <label for="sort-by" class="filter-label">Sort By</label>
        <select
          id="sort-by"
          v-model="filters.sortBy"
          class="filter-select"
          @change="onFilterChange"
        >
          <option value="name">Name</option>
          <option value="price">Price</option>
          <option value="createdAt">Newest</option>
        </select>
      </div>
      
      <div class="filter-group">
        <label for="sort-order" class="filter-label">Sort Order</label>
        <select
          id="sort-order"
          v-model="filters.sortOrder"
          class="filter-select"
          @change="onFilterChange"
        >
          <option value="asc">Ascending</option>
          <option value="desc">Descending</option>
        </select>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'ProductFilter',
  props: {
    categories: {
      type: Array,
      default: () => []
    },
    initialFilters: {
      type: Object,
      default: () => ({})
    }
  },
  data() {
    return {
      filters: {
        query: '',
        categoryId: '',
        minPrice: '',
        maxPrice: '',
        inStock: false,
        sortBy: 'name',
        sortOrder: 'asc',
        ...this.initialFilters
      }
    }
  },
  computed: {
    hasActiveFilters() {
      return Object.values(this.filters).some(value => 
        value !== '' && value !== false && value !== 'name' && value !== 'asc'
      );
    }
  },
  watch: {
    initialFilters: {
      handler(newFilters) {
        this.filters = { ...this.filters, ...newFilters };
      },
      deep: true
    }
  },
  methods: {
    onFilterChange() {
      // Debounce the filter change to avoid too many requests
      clearTimeout(this.debounceTimer);
      this.debounceTimer = setTimeout(() => {
        this.$emit('filter-change', { ...this.filters });
      }, 300);
    },
    clearFilters() {
      this.filters = {
        query: '',
        categoryId: '',
        minPrice: '',
        maxPrice: '',
        inStock: false,
        sortBy: 'name',
        sortOrder: 'asc'
      };
      this.$emit('filter-change', { ...this.filters });
    }
  }
}
</script>

<style scoped>
.product-filter {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 20px;
}

.product-filter__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid #e0e0e0;
}

.product-filter__header h3 {
  margin: 0;
  color: #333;
  font-size: 18px;
}

.clear-filters-btn {
  background: none;
  border: none;
  color: #2c5aa0;
  cursor: pointer;
  font-size: 14px;
  text-decoration: underline;
}

.clear-filters-btn:hover {
  color: #1e3d6f;
}

.filter-group {
  margin-bottom: 20px;
}

.filter-label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: #333;
  font-size: 14px;
}

.filter-input,
.filter-select {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  transition: border-color 0.2s ease;
}

.filter-input:focus,
.filter-select:focus {
  outline: none;
  border-color: #2c5aa0;
}

.price-range {
  display: flex;
  align-items: center;
  gap: 8px;
}

.price-input {
  flex: 1;
}

.price-range-separator {
  color: #666;
  font-size: 14px;
}

.filter-checkbox {
  display: flex;
  align-items: center;
  cursor: pointer;
  font-size: 14px;
  color: #333;
}

.filter-checkbox input {
  margin-right: 8px;
}

.checkmark {
  width: 18px;
  height: 18px;
  border: 2px solid #ddd;
  border-radius: 3px;
  margin-right: 8px;
  position: relative;
}

.filter-checkbox input:checked + .checkmark {
  background: #2c5aa0;
  border-color: #2c5aa0;
}

.filter-checkbox input:checked + .checkmark::after {
  content: '✓';
  color: white;
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  font-size: 12px;
}
</style>
```

### **📁 modules/catalog/presentation/views/ProductListView.vue**

```vue
<template>
  <div class="product-list-view">
    <div class="product-list-view__header">
      <h1>Products</h1>
      <p>Browse our catalog of amazing products</p>
    </div>
    
    <div class="product-list-view__content">
      <!-- Sidebar with filters -->
      <aside class="product-list-view__sidebar">
        <ProductFilter
          :categories="categories"
          :initial-filters="currentFilters"
          @filter-change="handleFilterChange"
        />
      </aside>
      
      <!-- Main content -->
      <main class="product-list-view__main">
        <div class="product-list-view__toolbar">
          <div class="results-count">
            Showing {{ filteredProducts.length }} products
          </div>
          <div class="view-options">
            <button 
              @click="toggleViewMode" 
              class="view-toggle-btn"
              :title="viewMode === 'grid' ? 'Switch to list view' : 'Switch to grid view'"
            >
              {{ viewMode === 'grid' ? '📋 List' : '📁 Grid' }}
            </button>
          </div>
        </div>
        
        <ProductList
          :products="paginatedProducts"
          :loading="loading"
          :pagination="pagination"
          @view-details="handleViewDetails"
          @add-to-cart="handleAddToCart"
          @page-change="handlePageChange"
          :class="['product-list-view__products', `product-list-view__products--${viewMode}`]"
        />
      </main>
    </div>
  </div>
</template>

<script>
import { SearchProductsUseCase } from '../../application/use-cases/search-products-use-case.js'
import { ProductRepository } from '../../infrastructure/persistence/product-repository.js'
import { CategoryRepository } from '../../infrastructure/persistence/category-repository.js'
import ProductFilter from '../components/ProductFilter.vue'
import ProductList from '../components/ProductList.vue'

export default {
  name: 'ProductListView',
  components: {
    ProductFilter,
    ProductList
  },
  data() {
    return {
      loading: false,
      products: [],
      categories: [],
      currentFilters: {
        query: '',
        categoryId: '',
        minPrice: '',
        maxPrice: '',
        inStock: false,
        sortBy: 'name',
        sortOrder: 'asc'
      },
      viewMode: 'grid',
      currentPage: 1,
      itemsPerPage: 12
    }
  },
  computed: {
    searchUseCase() {
      const productRepository = new ProductRepository()
      return new SearchProductsUseCase(productRepository)
    },
    filteredProducts() {
      // In a real app, this would be handled by the use case
      // For now, we'll do basic client-side filtering
      return this.products.filter(product => {
        const matchesQuery = !this.currentFilters.query || 
          product.name.toLowerCase().includes(this.currentFilters.query.toLowerCase()) ||
          product.description.toLowerCase().includes(this.currentFilters.query.toLowerCase())
        
        const matchesCategory = !this.currentFilters.categoryId || 
          product.categoryId === this.currentFilters.categoryId
        
        const matchesMinPrice = !this.currentFilters.minPrice || 
          product.price >= parseFloat(this.currentFilters.minPrice)
        
        const matchesMaxPrice = !this.currentFilters.maxPrice || 
          product.price <= parseFloat(this.currentFilters.maxPrice)
        
        const matchesStock = !this.currentFilters.inStock || product.isAvailable
        
        return matchesQuery && matchesCategory && matchesMinPrice && 
               matchesMaxPrice && matchesStock
      })
    },
    paginatedProducts() {
      const startIndex = (this.currentPage - 1) * this.itemsPerPage
      const endIndex = startIndex + this.itemsPerPage
      return this.filteredProducts.slice(startIndex, endIndex)
    },
    pagination() {
      const totalPages = Math.ceil(this.filteredProducts.length / this.itemsPerPage)
      return {
        currentPage: this.currentPage,
        totalPages: totalPages,
        hasNext: this.currentPage < totalPages,
        hasPrev: this.currentPage > 1
      }
    }
  },
  async created() {
    await this.loadCategories()
    await this.loadProducts()
  },
  methods: {
    async loadProducts() {
      this.loading = true
      try {
        // Use the search use case with current filters
        const searchCriteria = {
          ...this.currentFilters,
          page: this.currentPage,
          limit: this.itemsPerPage
        }
        
        this.products = await this.searchUseCase.execute(searchCriteria)
      } catch (error) {
        console.error('Error loading products:', error)
        this.$emit('error', error.message)
      } finally {
        this.loading = false
      }
    },
    
    async loadCategories() {
      try {
        const categoryRepository = new CategoryRepository()
        this.categories = await categoryRepository.findRootCategories()
      } catch (error) {
        console.error('Error loading categories:', error)
      }
    },
    
    handleFilterChange(filters) {
      this.currentFilters = filters
      this.currentPage = 1 // Reset to first page when filters change
      this.loadProducts()
    },
    
    handleViewDetails(product) {
      this.$router.push(`/products/${product.id}`)
    },
    
    handleAddToCart(product) {
      this.$emit('add-to-cart', product)
      // Show success message
      this.$notify({
        title: 'Added to Cart',
        message: `${product.name} has been added to your cart`,
        type: 'success'
      })
    },
    
    handlePageChange(page) {
      this.currentPage = page
      this.loadProducts()
      // Scroll to top when page changes
      window.scrollTo({ top: 0, behavior: 'smooth' })
    },
    
    toggleViewMode() {
      this.viewMode = this.viewMode === 'grid' ? 'list' : 'grid'
    }
  }
}
</script>

<style scoped>
.product-list-view {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.product-list-view__header {
  text-align: center;
  margin-bottom: 40px;
}

.product-list-view__header h1 {
  margin: 0 0 8px 0;
  color: #333;
  font-size: 2.5rem;
}

.product-list-view__header p {
  margin: 0;
  color: #666;
  font-size: 1.1rem;
}

.product-list-view__content {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 32px;
}

.product-list-view__sidebar {
  position: sticky;
  top: 20px;
  height: fit-content;
}

.product-list-view__main {
  min-height: 500px;
}

.product-list-view__toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  padding: 16px;
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
}

.results-count {
  color: #666;
  font-size: 14px;
}

.view-toggle-btn {
  background: none;
  border: 1px solid #ddd;
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s ease;
}

.view-toggle-btn:hover {
  background: #f5f5f5;
}

.product-list-view__products--grid {
  /* Grid styles are handled in ProductList component */
}

.product-list-view__products--list {
  /* List view styles would go here */
}

@media (max-width: 768px) {
  .product-list-view__content {
    grid-template-columns: 1fr;
    gap: 20px;
  }
  
  .product-list-view__sidebar {
    position: static;
  }
  
  .product-list-view__toolbar {
    flex-direction: column;
    gap: 12px;
    align-items: flex-start;
  }
}
</style>
```

### **📁 modules/catalog/presentation/views/ProductDetailView.vue**

Here's the continuation and completion of the `ProductDetailView.vue`:

```vue
<template>
  <div class="product-detail-view" v-if="product">
    <div class="product-detail-view__content">
      <!-- Product Images -->
      <div class="product-detail-view__gallery">
        <div class="main-image">
          <img 
            :src="selectedImage.url || product.images[0]?.url" 
            :alt="selectedImage.alt || product.name"
          >
        </div>
        <div class="image-thumbnails" v-if="product.images.length > 1">
          <div
            v-for="(image, index) in product.images"
            :key="index"
            class="thumbnail"
            :class="{ 'thumbnail--active': selectedImage.url === image.url }"
            @click="selectedImage = image"
          >
            <img :src="image.url" :alt="image.alt">
          </div>
        </div>
      </div>
      
      <!-- Product Info -->
      <div class="product-detail-view__info">
        <div class="product-header">
          <h1 class="product-title">{{ product.name }}</h1>
          <div class="product-sku">SKU: {{ product.sku }}</div>
        </div>
        
        <div class="product-price">
          {{ formattedPrice }}
        </div>
        
        <div class="product-status" :class="`product-status--${product.status}`">
          {{ statusLabel }}
        </div>
        
        <div class="product-description">
          <h3>Description</h3>
          <p>{{ product.description }}</p>
        </div>
        
        <div class="product-inventory" v-if="product.inventory">
          <h3>Availability</h3>
          <div class="inventory-info">
            <span class="inventory-quantity">
              {{ product.inventory.available }} in stock
            </span>
            <span 
              v-if="product.inventory.isLowStock" 
              class="low-stock-warning"
            >
              ⚠️ Low stock
            </span>
          </div>
        </div>
        
        <div class="product-actions">
          <div class="quantity-selector" v-if="product.isAvailable">
            <label for="quantity">Quantity:</label>
            <select 
              id="quantity" 
              v-model="quantity"
              class="quantity-select"
            >
              <option 
                v-for="n in maxQuantity" 
                :key="n" 
                :value="n"
              >
                {{ n }}
              </option>
            </select>
          </div>
          
          <button
            class="add-to-cart-btn"
            :disabled="!product.isAvailable"
            @click="addToCart"
          >
            {{ product.isAvailable ? 'Add to Cart' : 'Out of Stock' }}
          </button>
          
          <button class="wishlist-btn" @click="addToWishlist">
            ♡ Add to Wishlist
          </button>
        </div>
        
        <div class="product-meta">
          <div class="meta-item">
            <strong>Category:</strong>
            <span>{{ product.categoryName || 'Uncategorized' }}</span>
          </div>
          <div class="meta-item" v-if="product.tags && product.tags.length">
            <strong>Tags:</strong>
            <div class="tags">
              <span 
                v-for="tag in product.tags" 
                :key="tag" 
                class="tag"
              >
                {{ tag }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Product Tabs -->
    <div class="product-detail-view__tabs">
      <div class="tabs-header">
        <button 
          v-for="tab in tabs" 
          :key="tab.id"
          class="tab-btn"
          :class="{ 'tab-btn--active': activeTab === tab.id }"
          @click="activeTab = tab.id"
        >
          {{ tab.label }}
        </button>
      </div>
      
      <div class="tabs-content">
        <!-- Specifications Tab -->
        <div v-if="activeTab === 'specifications'" class="tab-panel">
          <div class="specifications">
            <div 
              v-for="spec in specifications" 
              :key="spec.name"
              class="spec-item"
            >
              <span class="spec-name">{{ spec.name }}:</span>
              <span class="spec-value">{{ spec.value }}</span>
            </div>
          </div>
        </div>
        
        <!-- Reviews Tab -->
        <div v-if="activeTab === 'reviews'" class="tab-panel">
          <div class="reviews-section">
            <div class="reviews-header">
              <div class="rating-overview">
                <div class="average-rating">
                  <span class="rating-stars">★★★★★</span>
                  <span class="rating-value">4.5 out of 5</span>
                </div>
                <div class="rating-count">Based on 128 reviews</div>
              </div>
              <button class="write-review-btn" @click="showReviewForm = true">
                Write a Review
              </button>
            </div>
            
            <div class="reviews-list">
              <div 
                v-for="review in reviews" 
                :key="review.id"
                class="review-item"
              >
                <div class="review-header">
                  <span class="reviewer-name">{{ review.reviewerName }}</span>
                  <span class="review-date">{{ formatDate(review.date) }}</span>
                </div>
                <div class="review-rating">
                  <span class="rating-stars">★★★★★</span>
                </div>
                <div class="review-title">{{ review.title }}</div>
                <div class="review-content">{{ review.content }}</div>
              </div>
            </div>
          </div>
        </div>
        
        <!-- Shipping Tab -->
        <div v-if="activeTab === 'shipping'" class="tab-panel">
          <div class="shipping-info">
            <div class="shipping-item">
              <h4>🚚 Free Shipping</h4>
              <p>Free standard shipping on orders over $50</p>
            </div>
            <div class="shipping-item">
              <h4>⏰ Delivery Time</h4>
              <p>3-5 business days for standard shipping</p>
            </div>
            <div class="shipping-item">
              <h4>📦 Returns</h4>
              <p>30-day return policy. No questions asked.</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Related Products -->
    <div class="related-products" v-if="relatedProducts.length > 0">
      <h2>Related Products</h2>
      <div class="related-products-grid">
        <ProductCard
          v-for="relatedProduct in relatedProducts"
          :key="relatedProduct.id"
          :product="relatedProduct"
          @view-details="handleViewDetails"
          @add-to-cart="handleAddToCart"
          class="related-product-item"
        />
      </div>
    </div>

    <!-- Review Form Modal -->
    <div v-if="showReviewForm" class="modal-overlay" @click="showReviewForm = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>Write a Review</h3>
          <button class="close-btn" @click="showReviewForm = false">×</button>
        </div>
        <div class="modal-body">
          <form @submit.prevent="submitReview">
            <div class="form-group">
              <label>Rating</label>
              <div class="rating-input">
                <span 
                  v-for="star in 5" 
                  :key="star"
                  class="star"
                  :class="{ 'star--active': newReview.rating >= star }"
                  @click="newReview.rating = star"
                >
                  ★
                </span>
              </div>
            </div>
            <div class="form-group">
              <label for="review-title">Title</label>
              <input
                id="review-title"
                v-model="newReview.title"
                type="text"
                placeholder="Summary of your review"
                required
              >
            </div>
            <div class="form-group">
              <label for="review-content">Review</label>
              <textarea
                id="review-content"
                v-model="newReview.content"
                placeholder="Share your experience with this product"
                rows="4"
                required
              ></textarea>
            </div>
            <div class="form-actions">
              <button type="button" @click="showReviewForm = false" class="btn-cancel">
                Cancel
              </button>
              <button type="submit" class="btn-submit">
                Submit Review
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
  
  <div v-else-if="loading" class="product-detail-view loading">
    <div class="loading-spinner"></div>
    <p>Loading product...</p>
  </div>
  
  <div v-else class="product-detail-view not-found">
    <h2>Product Not Found</h2>
    <p>The product you're looking for doesn't exist.</p>
    <button @click="$router.push('/products')" class="back-btn">
      Back to Products
    </button>
  </div>
</template>

<script>
import { GetProductUseCase } from '../../application/use-cases/get-product-use-case.js'
import { SearchProductsUseCase } from '../../application/use-cases/search-products-use-case.js'
import { ProductRepository } from '../../infrastructure/persistence/product-repository.js'
import ProductCard from '../components/ProductCard.vue'

export default {
  name: 'ProductDetailView',
  components: {
    ProductCard
  },
  data() {
    return {
      product: null,
      loading: false,
      selectedImage: {},
      quantity: 1,
      activeTab: 'specifications',
      showReviewForm: false,
      relatedProducts: [],
      newReview: {
        rating: 0,
        title: '',
        content: ''
      },
      tabs: [
        { id: 'specifications', label: 'Specifications' },
        { id: 'reviews', label: 'Reviews' },
        { id: 'shipping', label: 'Shipping & Returns' }
      ],
      specifications: [
        { name: 'Material', value: 'Premium Cotton' },
        { name: 'Dimensions', value: '10 x 8 x 2 inches' },
        { name: 'Weight', value: '1.2 lbs' },
        { name: 'Color', value: 'Various' },
        { name: 'Warranty', value: '1 Year Limited' }
      ],
      reviews: [
        {
          id: 1,
          reviewerName: 'John D.',
          date: new Date('2024-01-15'),
          rating: 5,
          title: 'Excellent product!',
          content: 'This product exceeded my expectations. The quality is outstanding and it arrived quickly.'
        },
        {
          id: 2,
          reviewerName: 'Sarah M.',
          date: new Date('2024-01-10'),
          rating: 4,
          title: 'Great value for money',
          content: 'Good quality product at a reasonable price. Would recommend to others.'
        }
      ]
    }
  },
  computed: {
    formattedPrice() {
      if (!this.product) return ''
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: this.product.currency || 'USD'
      }).format(this.product.price)
    },
    statusLabel() {
      if (!this.product) return ''
      const statusMap = {
        active: 'Available',
        inactive: 'Inactive',
        draft: 'Draft',
        discontinued: 'Discontinued',
        out_of_stock: 'Out of Stock'
      }
      return statusMap[this.product.status] || this.product.status
    },
    maxQuantity() {
      if (!this.product || !this.product.inventory) return 1
      return Math.min(this.product.inventory.available, 10)
    }
  },
  async created() {
    await this.loadProduct()
    await this.loadRelatedProducts()
  },
  watch: {
    '$route.params.id': {
      handler: 'loadProduct',
      immediate: false
    }
  },
  methods: {
    async loadProduct() {
      this.loading = true
      try {
        const productId = this.$route.params.id
        const getProductUseCase = new GetProductUseCase(new ProductRepository())
        this.product = await getProductUseCase.execute(productId)
        
        if (this.product && this.product.images.length > 0) {
          this.selectedImage = this.product.images[0]
        }
      } catch (error) {
        console.error('Error loading product:', error)
        this.$emit('error', error.message)
      } finally {
        this.loading = false
      }
    },

    async loadRelatedProducts() {
      try {
        const searchUseCase = new SearchProductsUseCase(new ProductRepository())
        this.relatedProducts = await searchUseCase.execute({
          categoryId: this.product?.categoryId,
          limit: 4
        })
      } catch (error) {
        console.error('Error loading related products:', error)
      }
    },
    
    addToCart() {
      if (this.product && this.product.isAvailable) {
        this.$emit('add-to-cart', {
          product: this.product,
          quantity: this.quantity
        })
        
        this.$notify({
          title: 'Added to Cart',
          message: `${this.quantity} x ${this.product.name} added to cart`,
          type: 'success'
        })
      }
    },
    
    addToWishlist() {
      this.$emit('add-to-wishlist', this.product)
      this.$notify({
        title: 'Added to Wishlist',
        message: `${this.product.name} added to wishlist`,
        type: 'success'
      })
    },

    handleViewDetails(product) {
      this.$router.push(`/products/${product.id}`)
    },

    handleAddToCart(product) {
      this.$emit('add-to-cart', product)
      this.$notify({
        title: 'Added to Cart',
        message: `${product.name} has been added to your cart`,
        type: 'success'
      })
    },

    formatDate(date) {
      return new Date(date).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      })
    },

    submitReview() {
      // In a real app, this would call an API
      const review = {
        id: Date.now(),
        reviewerName: 'You',
        date: new Date(),
        rating: this.newReview.rating,
        title: this.newReview.title,
        content: this.newReview.content
      }
      
      this.reviews.unshift(review)
      this.showReviewForm = false
      this.newReview = { rating: 0, title: '', content: '' }
      
      this.$notify({
        title: 'Review Submitted',
        message: 'Thank you for your review!',
        type: 'success'
      })
    }
  }
}
</script>

<style scoped>
.product-detail-view {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.product-detail-view__content {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 48px;
  align-items: start;
  margin-bottom: 60px;
}

.product-detail-view__gallery {
  position: sticky;
  top: 20px;
}

.main-image {
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  overflow: hidden;
  margin-bottom: 16px;
}

.main-image img {
  width: 100%;
  height: 400px;
  object-fit: cover;
}

.image-thumbnails {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.thumbnail {
  width: 60px;
  height: 60px;
  border: 2px solid transparent;
  border-radius: 4px;
  overflow: hidden;
  cursor: pointer;
  transition: all 0.2s ease;
}

.thumbnail:hover {
  border-color: #2c5aa0;
}

.thumbnail--active {
  border-color: #2c5aa0;
}

.thumbnail img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.product-detail-view__info {
  padding: 20px 0;
}

.product-header {
  margin-bottom: 16px;
}

.product-title {
  margin: 0 0 8px 0;
  font-size: 2rem;
  color: #333;
  line-height: 1.2;
}

.product-sku {
  color: #666;
  font-size: 14px;
}

.product-price {
  font-size: 2rem;
  font-weight: bold;
  color: #2c5aa0;
  margin-bottom: 16px;
}

.product-status {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 14px;
  font-weight: 500;
  margin-bottom: 24px;
}

.product-status--active {
  background: #e8f5e8;
  color: #2d5016;
}

.product-status--inactive {
  background: #f5f5f5;
  color: #666;
}

.product-status--out_of_stock {
  background: #ffe8e8;
  color: #d32f2f;
}

.product-description,
.product-inventory {
  margin-bottom: 24px;
}

.product-description h3,
.product-inventory h3 {
  margin: 0 0 8px 0;
  color: #333;
  font-size: 1.2rem;
}

.product-description p {
  margin: 0;
  color: #666;
  line-height: 1.6;
}

.inventory-info {
  display: flex;
  align-items: center;
  gap: 12px;
}

.inventory-quantity {
  font-weight: 500;
  color: #333;
}

.low-stock-warning {
  color: #d32f2f;
  font-size: 14px;
}

.product-actions {
  margin-bottom: 32px;
  padding: 24px;
  background: #f8f9fa;
  border-radius: 8px;
}

.quantity-selector {
  margin-bottom: 16px;
}

.quantity-selector label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: #333;
}

.quantity-select {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
}

.add-to-cart-btn {
  width: 100%;
  padding: 16px;
  background: #2c5aa0;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 1.1rem;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.2s ease;
  margin-bottom: 12px;
}

.add-to-cart-btn:hover:not(:disabled) {
  background: #1e3d6f;
}

.add-to-cart-btn:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.wishlist-btn {
  width: 100%;
  padding: 12px;
  background: white;
  color: #333;
  border: 1px solid #ddd;
  border-radius: 8px;
  font-size: 1rem;
  cursor: pointer;
  transition: all 0.2s ease;
}

.wishlist-btn:hover {
  background: #f5f5f5;
}

.product-meta {
  border-top: 1px solid #e0e0e0;
  padding-top: 24px;
}

.meta-item {
  margin-bottom: 16px;
}

.meta-item strong {
  display: block;
  margin-bottom: 4px;
  color: #333;
}

.tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
}

.tag {
  background: #e3f2fd;
  color: #1976d2;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
}

/* Tabs */
.product-detail-view__tabs {
  margin-bottom: 60px;
}

.tabs-header {
  display: flex;
  border-bottom: 1px solid #e0e0e0;
  margin-bottom: 32px;
}

.tab-btn {
  padding: 16px 24px;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  font-size: 16px;
  color: #666;
  transition: all 0.2s ease;
}

.tab-btn:hover {
  color: #2c5aa0;
}

.tab-btn--active {
  color: #2c5aa0;
  border-bottom-color: #2c5aa0;
}

.tab-panel {
  padding: 0 20px;
}

/* Specifications */
.specifications {
  display: grid;
  gap: 12px;
}

.spec-item {
  display: flex;
  justify-content: space-between;
  padding: 12px 0;
  border-bottom: 1px solid #f0f0f0;
}

.spec-name {
  font-weight: 500;
  color: #333;
}

.spec-value {
  color: #666;
}

/* Reviews */
.reviews-section {
  max-width: 600px;
}

.reviews-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 32px;
  padding: 24px;
  background: #f8f9fa;
  border-radius: 8px;
}

.average-rating {
  text-align: center;
}

.rating-stars {
  color: #ffc107;
  font-size: 24px;
}

.rating-value {
  display: block;
  font-size: 18px;
  font-weight: bold;
  margin-top: 4px;
}

.rating-count {
  color: #666;
  font-size: 14px;
  margin-top: 4px;
}

.write-review-btn {
  padding: 12px 24px;
  background: #2c5aa0;
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
}

.write-review-btn:hover {
  background: #1e3d6f;
}

.reviews-list {
  space-y: 24px;
}

.review-item {
  padding: 24px;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  margin-bottom: 16px;
}

.review-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 8px;
}

.reviewer-name {
  font-weight: 500;
  color: #333;
}

.review-date {
  color: #666;
  font-size: 14px;
}

.review-rating {
  margin-bottom: 8px;
}

.review-title {
  font-weight: 500;
  margin-bottom: 8px;
  color: #333;
}

.review-content {
  color: #666;
  line-height: 1.5;
}

/* Shipping */
.shipping-info {
  space-y: 24px;
}

.shipping-item {
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
  margin-bottom: 16px;
}

.shipping-item h4 {
  margin: 0 0 8px 0;
  color: #333;
}

.shipping-item p {
  margin: 0;
  color: #666;
}

/* Related Products */
.related-products {
  margin-top: 60px;
}

.related-products h2 {
  margin-bottom: 24px;
  color: #333;
  font-size: 1.5rem;
}

.related-products-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
}

/* Review Form Modal */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  border-radius: 8px;
  width: 90%;
  max-width: 500px;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid #e0e0e0;
}

.modal-header h3 {
  margin: 0;
  color: #333;
}

.close-btn {
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
  color: #666;
}

.close-btn:hover {
  color: #333;
}

.modal-body {
  padding: 24px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: #333;
}

.rating-input {
  display: flex;
  gap: 4px;
}

.star {
  font-size: 24px;
  color: #ddd;
  cursor: pointer;
  transition: color 0.2s ease;
}

.star--active {
  color: #ffc107;
}

.star:hover {
  color: #ffc107;
}

.form-group input,
.form-group textarea {
  width: 100%;
  padding: 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  transition: border-color 0.2s ease;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #2c5aa0;
}

.form-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  margin-top: 24px;
}

.btn-cancel {
  padding: 12px 24px;
  background: #f5f5f5;
  color: #333;
  border: 1px solid #ddd;
  border-radius: 4px;
  cursor: pointer;
}

.btn-cancel:hover {
  background: #e0e0e0;
}

.btn-submit {
  padding: 12px 24px;
  background: #2c5aa0;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.btn-submit:hover {
  background: #1e3d6f;
}

/* Loading and Error States */
.loading,
.not-found {
  text-align: center;
  padding: 60px 20px;
}

.loading-spinner {
  border: 3px solid #f3f3f3;
  border-top: 3px solid #2c5aa0;
  border-radius: 50%;
  width: 40px;
  height: 40px;
  animation: spin 1s linear infinite;
  margin: 0 auto 16px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.back-btn {
  padding: 12px 24px;
  background: #2c5aa0;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  margin-top: 16px;
}

.back-btn:hover {
  background: #1e3d6f;
}

/* Responsive Design */
@media (max-width: 768px) {
  .product-detail-view__content {
    grid-template-columns: 1fr;
    gap: 32px;
  }
  
  .product-detail-view__gallery {
    position: static;
  }
  
  .tabs-header {
    flex-direction: column;
  }
  
  .tab-btn {
    text-align: left;
  }
  
  .reviews-header {
    flex-direction: column;
    gap: 16px;
    text-align: center;
  }
  
  .related-products-grid {
    grid-template-columns: 1fr;
  }
}
</style>
```

## 🎯 **Missing Use Cases for Completion**

### **📁 modules/catalog/application/use-cases/get-product-use-case.js**

```javascript
export class GetProductUseCase {
  constructor(productRepository) {
    this.productRepository = productRepository;
  }

  async execute(productId) {
    const product = await this.productRepository.findById(productId);
    
    if (!product) {
      throw new Error(`Product with ID ${productId} not found`);
    }

    return {
      id: product.id.value,
      sku: product.sku.value,
      name: product.name,
      description: product.description,
      price: product.price.amount,
      currency: product.price.currency,
      status: product.status.value,
      categoryId: product.categoryId.value,
      images: product.images,
      tags: product.tags,
      isAvailable: product.isAvailable(),
      inventory: product.inventory ? {
        quantity: product.inventory.quantity,
        available: product.inventory.availableQuantity,
        reserved: product.inventory.reserved,
        isLowStock: product.inventory.isLowStock()
      } : null,
      createdAt: product.createdAt,
      updatedAt: product.updatedAt
    };
  }
}
```

## 🔧 **Vue 2 App Integration**

### **📁 main.js** (Vue 2 Entry Point)

```javascript
import Vue from 'vue'
import App from './App.vue'
import router from './router'

// Import catalog components
import ProductListView from './modules/catalog/presentation/views/ProductListView.vue'
import ProductDetailView from './modules/catalog/presentation/views/ProductDetailView.vue'

// Register global components
Vue.component('ProductCard', () => import('./modules/catalog/presentation/components/ProductCard.vue'))
Vue.component('ProductList', () => import('./modules/catalog/presentation/components/ProductList.vue'))
Vue.component('ProductFilter', () => import('./modules/catalog/presentation/components/ProductFilter.vue'))

// Vue notification plugin (example)
Vue.prototype.$notify = function(options) {
  // Implementation depends on your notification library
  console.log('Notification:', options)
}

new Vue({
  router,
  render: h => h(App)
}).$mount('#app')
```

### **📁 router/index.js**

```javascript
import Vue from 'vue'
import Router from 'vue-router'
import ProductListView from '../modules/catalog/presentation/views/ProductListView.vue'
import ProductDetailView from '../modules/catalog/presentation/views/ProductDetailView.vue'

Vue.use(Router)

export default new Router({
  mode: 'history',
  routes: [
    {
      path: '/products',
      name: 'products',
      component: ProductListView
    },
    {
      path: '/products/:id',
      name: 'product-detail',
      component: ProductDetailView,
      props: true
    },
    {
      path: '/',
      redirect: '/products'
    }
  ]
})
```

This completes the Vue.js 2 implementation of the Catalog module with:

- **Complete Product Detail View** with tabs, reviews, and related products
- **Responsive Design** for mobile and desktop
- **Vue 2 Compatibility** using Options API
- **Full DDD Integration** with use cases and repositories
- **Interactive Features** like image gallery, review system, and add to cart
- **Professional UI/UX** with proper loading states and error handling

The implementation maintains clean separation between presentation and domain logic while leveraging Vue 2's reactivity system for a smooth user experience.

Here's the complete Vue.js 2 implementation of the Orders module:

## 🏗️ **Orders Module Structure**

```
modules/
└── orders/
    ├── domain/
    │   ├── entities/
    │   ├── value-objects/
    │   └── services/
    ├── application/
    │   ├── use-cases/
    │   └── ports/
    ├── infrastructure/
    │   └── persistence/
    └── presentation/
        ├── components/
        │   ├── OrderSummary.vue
        │   ├── OrderItem.vue
        │   └── CheckoutForm.vue
        └── views/
            ├── OrderHistoryView.vue
            └── CheckoutView.vue
```

## 📦 **Orders Domain Implementation**

### **📁 modules/orders/domain/value-objects/**

#### **order-status.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';

export class OrderStatus extends ValueObject {
  static PENDING = new OrderStatus('pending');
  static CONFIRMED = new OrderStatus('confirmed');
  static PROCESSING = new OrderStatus('processing');
  static SHIPPED = new OrderStatus('shipped');
  static DELIVERED = new OrderStatus('delivered');
  static CANCELLED = new OrderStatus('cancelled');
  static REFUNDED = new OrderStatus('refunded');

  constructor(value) {
    super();
    this.value = value;
  }

  canBeCancelled() {
    return [OrderStatus.PENDING.value, OrderStatus.CONFIRMED.value].includes(this.value);
  }

  canBeModified() {
    return this.value === OrderStatus.PENDING.value;
  }

  isCompleted() {
    return [OrderStatus.DELIVERED.value, OrderStatus.CANCELLED.value, OrderStatus.REFUNDED.value].includes(this.value);
  }

  toString() {
    return this.value;
  }
}
```

#### **address.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';
import { DomainError } from '../../../../shared/errors/domain-errors.js';

export class InvalidAddressError extends DomainError {}

export class Address extends ValueObject {
  constructor(street, city, state, zipCode, country = 'US') {
    super();
    this.street = street.trim();
    this.city = city.trim();
    this.state = state.trim();
    this.zipCode = zipCode.trim();
    this.country = country.trim();
    this.#validate();
  }

  #validate() {
    if (!this.street || this.street.length < 5) {
      throw new InvalidAddressError('Street address must be at least 5 characters long');
    }
    
    if (!this.city || this.city.length < 2) {
      throw new InvalidAddressError('City is required');
    }
    
    if (!this.state || this.state.length < 2) {
      throw new InvalidAddressError('State is required');
    }
    
    const zipRegex = /^\d{5}(-\d{4})?$/;
    if (!zipRegex.test(this.zipCode)) {
      throw new InvalidAddressError('Invalid ZIP code format');
    }
  }

  format() {
    return `${this.street}, ${this.city}, ${this.state} ${this.zipCode}, ${this.country}`;
  }

  equals(other) {
    return this.street === other.street &&
           this.city === other.city &&
           this.state === other.state &&
           this.zipCode === other.zipCode &&
           this.country === other.country;
  }
}
```

#### **payment-method.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';

export class PaymentMethod extends ValueObject {
  static CREDIT_CARD = new PaymentMethod('credit_card');
  static DEBIT_CARD = new PaymentMethod('debit_card');
  static PAYPAL = new PaymentMethod('paypal');
  static BANK_TRANSFER = new PaymentMethod('bank_transfer');
  static CRYPTO = new PaymentMethod('crypto');

  constructor(value) {
    super();
    this.value = value;
  }

  isCard() {
    return [PaymentMethod.CREDIT_CARD.value, PaymentMethod.DEBIT_CARD.value].includes(this.value);
  }

  isDigital() {
    return [PaymentMethod.PAYPAL.value, PaymentMethod.CRYPTO.value].includes(this.value);
  }

  toString() {
    return this.value;
  }
}
```

### **📁 modules/orders/domain/entities/**

#### **order-id.js**
```javascript
import { ValueObject } from '../../../../shared/utils/value-object.js';

export class OrderId extends ValueObject {
  constructor(value) {
    super();
    this.value = value;
  }

  static generate() {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 9);
    return new OrderId(`ORD-${timestamp}-${random}`.toUpperCase());
  }

  toString() {
    return this.value;
  }
}
```

#### **order-item.js**
```javascript
import { Entity } from './entity.js';
import { ProductId } from '../../../catalog/domain/entities/product-id.js';
import { Price } from '../../../catalog/domain/value-objects/price.js';

export class OrderItem extends Entity {
  constructor(id, productId, productName, unitPrice, quantity, imageUrl = '') {
    super(id);
    this.productId = productId;
    this.productName = productName;
    this.unitPrice = unitPrice;
    this.quantity = quantity;
    this.imageUrl = imageUrl;
  }

  get subtotal() {
    return this.unitPrice.multiply(this.quantity);
  }

  updateQuantity(newQuantity) {
    if (newQuantity < 1) {
      throw new Error('Quantity must be at least 1');
    }
    this.quantity = newQuantity;
  }

  increaseQuantity(amount = 1) {
    this.quantity += amount;
  }

  decreaseQuantity(amount = 1) {
    if (this.quantity - amount < 1) {
      throw new Error('Quantity cannot be less than 1');
    }
    this.quantity -= amount;
  }
}
```

#### **payment.js**
```javascript
import { Entity } from './entity.js';
import { PaymentMethod } from '../value-objects/payment-method.js';

export class Payment extends Entity {
  constructor(id, orderId, amount, paymentMethod, status = 'pending') {
    super(id);
    this.orderId = orderId;
    this.amount = amount;
    this.paymentMethod = paymentMethod;
    this.status = status;
    this.transactionId = null;
    this.processedAt = null;
    this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  process(transactionId) {
    if (this.status !== 'pending') {
      throw new Error('Payment can only be processed when in pending status');
    }
    
    this.status = 'completed';
    this.transactionId = transactionId;
    this.processedAt = new Date();
    this.updatedAt = new Date();
    
    this.addDomainEvent({
      type: 'PAYMENT_PROCESSED',
      paymentId: this.id,
      orderId: this.orderId,
      amount: this.amount
    });
  }

  fail(reason) {
    this.status = 'failed';
    this.failureReason = reason;
    this.updatedAt = new Date();
    
    this.addDomainEvent({
      type: 'PAYMENT_FAILED',
      paymentId: this.id,
      orderId: this.orderId,
      reason: reason
    });
  }

  refund(amount = this.amount) {
    if (this.status !== 'completed') {
      throw new Error('Only completed payments can be refunded');
    }
    
    if (amount > this.amount) {
      throw new Error('Refund amount cannot exceed original payment amount');
    }
    
    this.status = 'refunded';
    this.refundAmount = amount;
    this.updatedAt = new Date();
    
    this.addDomainEvent({
      type: 'PAYMENT_REFUNDED',
      paymentId: this.id,
      orderId: this.orderId,
      amount: amount
    });
  }

  isSuccessful() {
    return this.status === 'completed';
  }

  isPending() {
    return this.status === 'pending';
  }
}
```

#### **order.js**
```javascript
import { Entity } from './entity.js';
import { OrderId } from './order-id.js';
import { OrderStatus } from '../value-objects/order-status.js';
import { Address } from '../value-objects/address.js';
import { Price } from '../../../catalog/domain/value-objects/price.js';

export class Order extends Entity {
  constructor(id, customerId, shippingAddress, items = []) {
    super(id);
    this.customerId = customerId;
    this.shippingAddress = shippingAddress;
    this.items = items;
    this.status = OrderStatus.PENDING;
    this.payment = null;
    this.shippingCost = new Price(0, 'USD');
    this.taxAmount = new Price(0, 'USD');
    this.discountAmount = new Price(0, 'USD');
    this.createdAt = new Date();
    this.updatedAt = new Date();
    this.notes = '';
  }

  addItem(productId, productName, unitPrice, quantity, imageUrl = '') {
    const existingItem = this.items.find(item => item.productId.equals(productId));
    
    if (existingItem) {
      existingItem.increaseQuantity(quantity);
    } else {
      const itemId = `item_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const newItem = new OrderItem(
        itemId,
        productId,
        productName,
        unitPrice,
        quantity,
        imageUrl
      );
      this.items.push(newItem);
    }
    
    this.updatedAt = new Date();
  }

  removeItem(productId) {
    this.items = this.items.filter(item => !item.productId.equals(productId));
    this.updatedAt = new Date();
  }

  updateItemQuantity(productId, newQuantity) {
    const item = this.items.find(item => item.productId.equals(productId));
    if (item) {
      item.updateQuantity(newQuantity);
      this.updatedAt = new Date();
    }
  }

  get subtotal() {
    return this.items.reduce(
      (total, item) => total.add(item.subtotal),
      new Price(0, 'USD')
    );
  }

  get total() {
    return this.subtotal
      .add(this.shippingCost)
      .add(this.taxAmount)
      .subtract(this.discountAmount);
  }

  get itemCount() {
    return this.items.reduce((count, item) => count + item.quantity, 0);
  }

  confirm() {
    if (this.status !== OrderStatus.PENDING) {
      throw new Error('Only pending orders can be confirmed');
    }
    
    if (this.items.length === 0) {
      throw new Error('Cannot confirm an empty order');
    }
    
    this.status = OrderStatus.CONFIRMED;
    this.updatedAt = new Date();
    
    this.addDomainEvent({
      type: 'ORDER_CONFIRMED',
      orderId: this.id,
      customerId: this.customerId,
      total: this.total
    });
  }

  cancel(reason = '') {
    if (!this.status.canBeCancelled()) {
      throw new Error(`Order cannot be cancelled in current status: ${this.status}`);
    }
    
    this.status = OrderStatus.CANCELLED;
    this.cancellationReason = reason;
    this.updatedAt = new Date();
    
    this.addDomainEvent({
      type: 'ORDER_CANCELLED',
      orderId: this.id,
      customerId: this.customerId,
      reason: reason
    });
  }

  ship(trackingNumber) {
    if (this.status !== OrderStatus.CONFIRMED && this.status !== OrderStatus.PROCESSING) {
      throw new Error('Only confirmed or processing orders can be shipped');
    }
    
    this.status = OrderStatus.SHIPPED;
    this.trackingNumber = trackingNumber;
    this.shippedAt = new Date();
    this.updatedAt = new Date();
    
    this.addDomainEvent({
      type: 'ORDER_SHIPPED',
      orderId: this.id,
      customerId: this.customerId,
      trackingNumber: trackingNumber
    });
  }

  deliver() {
    if (this.status !== OrderStatus.SHIPPED) {
      throw new Error('Only shipped orders can be delivered');
    }
    
    this.status = OrderStatus.DELIVERED;
    this.deliveredAt = new Date();
    this.updatedAt = new Date();
    
    this.addDomainEvent({
      type: 'ORDER_DELIVERED',
      orderId: this.id,
      customerId: this.customerId
    });
  }

  setPayment(payment) {
    this.payment = payment;
    this.updatedAt = new Date();
  }

  setShippingCost(cost) {
    this.shippingCost = cost;
    this.updatedAt = new Date();
  }

  setTaxAmount(amount) {
    this.taxAmount = amount;
    this.updatedAt = new Date();
  }

  applyDiscount(amount) {
    this.discountAmount = amount;
    this.updatedAt = new Date();
  }

  isPaid() {
    return this.payment && this.payment.isSuccessful();
  }

  canBeModified() {
    return this.status.canBeModified();
  }

  isEmpty() {
    return this.items.length === 0;
  }
}
```

### **📁 modules/orders/domain/services/**

#### **order-service.js**
```javascript
export class OrderService {
  calculateShippingCost(order, shippingMethod = 'standard') {
    const baseCost = 5.00; // $5 base shipping
    const weightCost = order.itemCount * 0.5; // $0.50 per item
    let methodMultiplier = 1;
    
    switch (shippingMethod) {
      case 'express':
        methodMultiplier = 2.5;
        break;
      case 'overnight':
        methodMultiplier = 4;
        break;
      case 'standard':
      default:
        methodMultiplier = 1;
    }
    
    const totalCost = (baseCost + weightCost) * methodMultiplier;
    return new Price(totalCost, 'USD');
  }

  calculateTax(order, taxRate = 0.08) {
    const taxableAmount = order.subtotal.add(order.shippingCost).amount;
    const taxAmount = taxableAmount * taxRate;
    return new Price(taxAmount, 'USD');
  }

  validateOrderForCheckout(order) {
    const errors = [];
    
    if (order.isEmpty()) {
      errors.push('Order must contain at least one item');
    }
    
    if (!order.shippingAddress) {
      errors.push('Shipping address is required');
    }
    
    if (order.items.some(item => item.quantity < 1)) {
      errors.push('All items must have a quantity of at least 1');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }

  generateOrderSummary(order) {
    return {
      itemCount: order.itemCount,
      subtotal: order.subtotal,
      shippingCost: order.shippingCost,
      taxAmount: order.taxAmount,
      discountAmount: order.discountAmount,
      total: order.total,
      status: order.status.value
    };
  }
}
```

#### **payment-service.js**
```javascript
export class PaymentService {
  processPayment(payment, paymentDetails) {
    // Validate payment details based on payment method
    switch (payment.paymentMethod.value) {
      case 'credit_card':
      case 'debit_card':
        if (!this.#validateCardDetails(paymentDetails)) {
          throw new Error('Invalid card details');
        }
        break;
      case 'paypal':
        if (!paymentDetails.email || !paymentDetails.transactionId) {
          throw new Error('Invalid PayPal details');
        }
        break;
      default:
        throw new Error(`Unsupported payment method: ${payment.paymentMethod}`);
    }
    
    // Simulate payment processing
    const isSuccessful = Math.random() > 0.1; // 90% success rate for demo
    
    if (isSuccessful) {
      const transactionId = `TXN-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`.toUpperCase();
      payment.process(transactionId);
      return { success: true, transactionId };
    } else {
      payment.fail('Payment was declined by the processor');
      return { success: false, error: 'Payment declined' };
    }
  }

  #validateCardDetails(cardDetails) {
    const { cardNumber, expiryMonth, expiryYear, cvv } = cardDetails;
    
    // Basic validation
    if (!cardNumber || cardNumber.replace(/\s/g, '').length !== 16) {
      return false;
    }
    
    if (!expiryMonth || expiryMonth < 1 || expiryMonth > 12) {
      return false;
    }
    
    const currentYear = new Date().getFullYear();
    if (!expiryYear || expiryYear < currentYear) {
      return false;
    }
    
    if (!cvv || cvv.length !== 3) {
      return false;
    }
    
    return true;
  }

  calculateRefundAmount(payment, refundReason) {
    // Different refund policies based on reason
    const refundPolicies = {
      'defective': 1.0, // Full refund for defective products
      'dissatisfied': 0.8, // 80% refund for dissatisfaction
      'change_of_mind': 0.5, // 50% refund for change of mind
      'default': 0.9 // 90% refund by default
    };
    
    const refundRate = refundPolicies[refundReason] || refundPolicies['default'];
    return payment.amount.multiply(refundRate);
  }
}
```

## 🚀 **Orders Application Layer**

### **📁 modules/orders/application/ports/**

#### **order-repository.js**
```javascript
export class IOrderRepository {
  async save(order) {
    throw new Error('Method not implemented');
  }

  async findById(id) {
    throw new Error('Method not implemented');
  }

  async findByCustomerId(customerId) {
    throw new Error('Method not implemented');
  }

  async findByStatus(status) {
    throw new Error('Method not implemented');
  }

  async updateStatus(orderId, status) {
    throw new Error('Method not implemented');
  }

  async delete(orderId) {
    throw new Error('Method not implemented');
  }
}
```

#### **payment-gateway.js**
```javascript
export class IPaymentGateway {
  async processPayment(payment, paymentDetails) {
    throw new Error('Method not implemented');
  }

  async refundPayment(transactionId, amount) {
    throw new Error('Method not implemented');
  }

  async getPaymentStatus(transactionId) {
    throw new Error('Method not implemented');
  }
}
```

### **📁 modules/orders/application/use-cases/**

#### **create-order-use-case.js**
```javascript
import { Order } from '../../domain/entities/order.js';
import { OrderId } from '../../domain/entities/order-id.js';
import { OrderService } from '../../domain/services/order-service.js';

export class CreateOrderUseCase {
  constructor(orderRepository) {
    this.orderRepository = orderRepository;
    this.orderService = new OrderService();
  }

  async execute(command) {
    const { customerId, shippingAddress, items, shippingMethod = 'standard' } = command;

    // Create order
    const orderId = OrderId.generate();
    const order = new Order(orderId, customerId, shippingAddress);

    // Add items to order
    items.forEach(item => {
      order.addItem(
        item.productId,
        item.productName,
        item.unitPrice,
        item.quantity,
        item.imageUrl
      );
    });

    // Calculate costs
    const shippingCost = this.orderService.calculateShippingCost(order, shippingMethod);
    const taxAmount = this.orderService.calculateTax(order);

    order.setShippingCost(shippingCost);
    order.setTaxAmount(taxAmount);

    // Validate order
    const validation = this.orderService.validateOrderForCheckout(order);
    if (!validation.isValid) {
      throw new Error(`Order validation failed: ${validation.errors.join(', ')}`);
    }

    // Save order
    await this.orderRepository.save(order);

    return {
      id: order.id.value,
      customerId: order.customerId,
      status: order.status.value,
      subtotal: order.subtotal.amount,
      shippingCost: order.shippingCost.amount,
      taxAmount: order.taxAmount.amount,
      total: order.total.amount,
      itemCount: order.itemCount,
      items: order.items.map(item => ({
        productId: item.productId.value,
        productName: item.productName,
        unitPrice: item.unitPrice.amount,
        quantity: item.quantity,
        subtotal: item.subtotal.amount
      }))
    };
  }
}
```

#### **process-payment-use-case.js**
```javascript
import { Payment } from '../../domain/entities/payment.js';
import { PaymentMethod } from '../../domain/value-objects/payment-method.js';
import { PaymentService } from '../../domain/services/payment-service.js';

export class ProcessPaymentUseCase {
  constructor(orderRepository, paymentGateway) {
    this.orderRepository = orderRepository;
    this.paymentGateway = paymentGateway;
    this.paymentService = new PaymentService();
  }

  async execute(command) {
    const { orderId, paymentMethod, paymentDetails, amount } = command;

    // Get order
    const order = await this.orderRepository.findById(orderId);
    if (!order) {
      throw new Error(`Order not found: ${orderId}`);
    }

    // Verify order can accept payment
    if (order.isPaid()) {
      throw new Error('Order is already paid');
    }

    if (!order.status.canBeModified()) {
      throw new Error(`Cannot process payment for order in status: ${order.status}`);
    }

    // Create payment
    const paymentId = `pay_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const method = new PaymentMethod(paymentMethod);
    const payment = new Payment(paymentId, orderId, amount, method);

    // Process payment
    const result = await this.paymentGateway.processPayment(payment, paymentDetails);

    if (result.success) {
      order.setPayment(payment);
      order.confirm();
      await this.orderRepository.save(order);
    }

    return {
      success: result.success,
      paymentId: payment.id,
      transactionId: payment.transactionId,
      orderStatus: order.status.value,
      message: result.success ? 'Payment processed successfully' : result.error
    };
  }
}
```

#### **cancel-order-use-case.js**
```javascript
export class CancelOrderUseCase {
  constructor(orderRepository) {
    this.orderRepository = orderRepository;
  }

  async execute(command) {
    const { orderId, reason = '' } = command;

    const order = await this.orderRepository.findById(orderId);
    if (!order) {
      throw new Error(`Order not found: ${orderId}`);
    }

    order.cancel(reason);
    await this.orderRepository.save(order);

    return {
      id: order.id.value,
      status: order.status.value,
      cancelledAt: order.updatedAt,
      reason: order.cancellationReason
    };
  }
}
```

## 💾 **Orders Infrastructure**

### **📁 modules/orders/infrastructure/persistence/**

#### **order-repository.js**
```javascript
import { IOrderRepository } from '../../application/ports/order-repository.js';
import { Order } from '../../domain/entities/order.js';
import { OrderId } from '../../domain/entities/order-id.js';
import { OrderStatus } from '../../domain/value-objects/order-status.js';
import { Address } from '../../domain/value-objects/address.js';
import { Price } from '../../../catalog/domain/value-objects/price.js';
import { OrderItem } from '../../domain/entities/order-item.js';
import { ProductId } from '../../../catalog/domain/entities/product-id.js';
import { Payment } from '../../domain/entities/payment.js';
import { PaymentMethod } from '../../domain/value-objects/payment-method.js';

export class OrderRepository extends IOrderRepository {
  constructor(storage = localStorage) {
    super();
    this.storage = storage;
    this.key = 'orders_data';
  }

  async save(order) {
    const orders = this.#getAllOrders();
    const orderData = this.#toPersistence(order);
    
    const existingIndex = orders.findIndex(o => o.id === order.id.value);
    if (existingIndex >= 0) {
      orders[existingIndex] = orderData;
    } else {
      orders.push(orderData);
    }
    
    this.storage.setItem(this.key, JSON.stringify(orders));
  }

  async findById(id) {
    const orders = this.#getAllOrders();
    const orderData = orders.find(o => o.id === id.value);
    return orderData ? this.#toDomain(orderData) : null;
  }

  async findByCustomerId(customerId) {
    const orders = this.#getAllOrders();
    const customerOrders = orders.filter(o => o.customerId === customerId);
    return customerOrders.map(data => this.#toDomain(data)).sort((a, b) => 
      new Date(b.createdAt) - new Date(a.createdAt)
    );
  }

  async findByStatus(status) {
    const orders = this.#getAllOrders();
    const statusOrders = orders.filter(o => o.status === status.value);
    return statusOrders.map(data => this.#toDomain(data));
  }

  async updateStatus(orderId, status) {
    const orders = this.#getAllOrders();
    const orderIndex = orders.findIndex(o => o.id === orderId.value);
    
    if (orderIndex >= 0) {
      orders[orderIndex].status = status.value;
      orders[orderIndex].updatedAt = new Date().toISOString();
      this.storage.setItem(this.key, JSON.stringify(orders));
    }
  }

  async delete(orderId) {
    const orders = this.#getAllOrders();
    const filteredOrders = orders.filter(o => o.id !== orderId.value);
    this.storage.setItem(this.key, JSON.stringify(filteredOrders));
  }

  #getAllOrders() {
    const data = this.storage.getItem(this.key);
    return data ? JSON.parse(data) : [];
  }

  #toPersistence(order) {
    return {
      id: order.id.value,
      customerId: order.customerId,
      shippingAddress: {
        street: order.shippingAddress.street,
        city: order.shippingAddress.city,
        state: order.shippingAddress.state,
        zipCode: order.shippingAddress.zipCode,
        country: order.shippingAddress.country
      },
      items: order.items.map(item => ({
        id: item.id,
        productId: item.productId.value,
        productName: item.productName,
        unitPrice: item.unitPrice.amount,
        currency: item.unitPrice.currency,
        quantity: item.quantity,
        imageUrl: item.imageUrl
      })),
      status: order.status.value,
      payment: order.payment ? {
        id: order.payment.id,
        amount: order.payment.amount.amount,
        currency: order.payment.amount.currency,
        paymentMethod: order.payment.paymentMethod.value,
        status: order.payment.status,
        transactionId: order.payment.transactionId,
        processedAt: order.payment.processedAt?.toISOString()
      } : null,
      shippingCost: order.shippingCost.amount,
      taxAmount: order.taxAmount.amount,
      discountAmount: order.discountAmount.amount,
      notes: order.notes,
      createdAt: order.createdAt.toISOString(),
      updatedAt: order.updatedAt.toISOString()
    };
  }

  #toDomain(orderData) {
    const orderId = new OrderId(orderData.id);
    const shippingAddress = new Address(
      orderData.shippingAddress.street,
      orderData.shippingAddress.city,
      orderData.shippingAddress.state,
      orderData.shippingAddress.zipCode,
      orderData.shippingAddress.country
    );

    const order = new Order(orderId, orderData.customerId, shippingAddress);

    // Restore items
    orderData.items.forEach(itemData => {
      const productId = new ProductId(itemData.productId);
      const unitPrice = new Price(itemData.unitPrice, itemData.currency);
      
      const orderItem = new OrderItem(
        itemData.id,
        productId,
        itemData.productName,
        unitPrice,
        itemData.quantity,
        itemData.imageUrl
      );
      
      order.items.push(orderItem);
    });

    // Restore status
    order.status = new OrderStatus(orderData.status);

    // Restore payment if exists
    if (orderData.payment) {
      const paymentAmount = new Price(orderData.payment.amount, orderData.payment.currency);
      const paymentMethod = new PaymentMethod(orderData.payment.paymentMethod);
      
      const payment = new Payment(
        orderData.payment.id,
        orderId,
        paymentAmount,
        paymentMethod,
        orderData.payment.status
      );
      
      payment.transactionId = orderData.payment.transactionId;
      if (orderData.payment.processedAt) {
        payment.processedAt = new Date(orderData.payment.processedAt);
      }
      
      order.setPayment(payment);
    }

    // Restore costs
    order.setShippingCost(new Price(orderData.shippingCost, 'USD'));
    order.setTaxAmount(new Price(orderData.taxAmount, 'USD'));
    order.applyDiscount(new Price(orderData.discountAmount, 'USD'));

    order.notes = orderData.notes;
    order.createdAt = new Date(orderData.createdAt);
    order.updatedAt = new Date(orderData.updatedAt);

    return order;
  }
}
```

#### **payment-adapter.js**
```javascript
import { IPaymentGateway } from '../../application/ports/payment-gateway.js';

export class PaymentAdapter extends IPaymentGateway {
  constructor(apiBaseUrl = 'https://api.payment.example.com') {
    super();
    this.apiBaseUrl = apiBaseUrl;
  }

  async processPayment(payment, paymentDetails) {
    // Simulate API call to payment gateway
    return new Promise((resolve) => {
      setTimeout(() => {
        // Demo logic - in real app, this would call actual payment API
        const isSuccess = Math.random() > 0.1; // 90% success rate
        
        if (isSuccess) {
          const transactionId = `TXN-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`.toUpperCase();
          resolve({
            success: true,
            transactionId: transactionId,
            message: 'Payment processed successfully'
          });
        } else {
          resolve({
            success: false,
            error: 'Payment was declined by the processor',
            errorCode: 'DECLINED'
          });
        }
      }, 2000); // Simulate network delay
    });
  }

  async refundPayment(transactionId, amount) {
    // Simulate refund API call
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          success: true,
          refundId: `REF-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`.toUpperCase(),
          amount: amount.amount,
          message: 'Refund processed successfully'
        });
      }, 1500);
    });
  }

  async getPaymentStatus(transactionId) {
    // Simulate status check API call
    return new Promise((resolve) => {
      setTimeout(() => {
        const statuses = ['completed', 'pending', 'failed'];
        const randomStatus = statuses[Math.floor(Math.random() * statuses.length)];
        
        resolve({
          status: randomStatus,
          transactionId: transactionId,
          lastUpdated: new Date().toISOString()
        });
      }, 500);
    });
  }
}
```

## 🎨 **Orders Presentation Layer (Vue.js 2)**

### **📁 modules/orders/presentation/components/OrderItem.vue**

```vue
<template>
  <div class="order-item" :class="{ 'order-item--editable': editable }">
    <div class="order-item__image">
      <img :src="item.imageUrl || '/placeholder-product.jpg'" :alt="item.productName">
    </div>
    
    <div class="order-item__details">
      <h4 class="order-item__name">{{ item.productName }}</h4>
      <div class="order-item__sku">SKU: {{ item.productId }}</div>
      
      <div class="order-item__price">
        {{ formatCurrency(item.unitPrice) }} each
      </div>
    </div>
    
    <div class="order-item__quantity">
      <div v-if="editable" class="quantity-controls">
        <button 
          @click="decreaseQuantity" 
          :disabled="item.quantity <= 1"
          class="quantity-btn"
        >
          −
        </button>
        <span class="quantity-display">{{ item.quantity }}</span>
        <button @click="increaseQuantity" class="quantity-btn">+</button>
      </div>
      <div v-else class="quantity-static">
        Qty: {{ item.quantity }}
      </div>
    </div>
    
    <div class="order-item__subtotal">
      {{ formatCurrency(item.subtotal) }}
    </div>
    
    <div v-if="editable" class="order-item__actions">
      <button @click="removeItem" class="remove-btn" title="Remove item">
        🗑️
      </button>
    </div>
  </div>
</template>

<script>
export default {
  name: 'OrderItem',
  props: {
    item: {
      type: Object,
      required: true
    },
    editable: {
      type: Boolean,
      default: false
    }
  },
  methods: {
    formatCurrency(amount) {
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
      }).format(amount);
    },
    
    increaseQuantity() {
      this.$emit('update-quantity', {
        productId: this.item.productId,
        quantity: this.item.quantity + 1
      });
    },
    
    decreaseQuantity() {
      if (this.item.quantity > 1) {
        this.$emit('update-quantity', {
          productId: this.item.productId,
          quantity: this.item.quantity - 1
        });
      }
    },
    
    removeItem() {
      this.$emit('remove-item', this.item.productId);
    }
  }
}
</script>

<style scoped>
Here's the continuation and completion of the Orders module Vue.js 2 implementation:

### **📁 modules/orders/presentation/components/OrderItem.vue** (continued)

```vue
<style scoped>
.order-item {
  display: grid;
  grid-template-columns: 80px 1fr auto auto;
  gap: 16px;
  align-items: center;
  padding: 16px;
  border-bottom: 1px solid #e0e0e0;
}

.order-item--editable {
  grid-template-columns: 80px 1fr auto auto auto;
}

.order-item__image {
  width: 80px;
  height: 80px;
  border-radius: 8px;
  overflow: hidden;
}

.order-item__image img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.order-item__details {
  min-width: 0;
}

.order-item__name {
  margin: 0 0 4px 0;
  font-size: 16px;
  font-weight: 500;
  color: #333;
}

.order-item__sku {
  font-size: 12px;
  color: #666;
  margin-bottom: 4px;
}

.order-item__price {
  font-size: 14px;
  color: #2c5aa0;
  font-weight: 500;
}

.order-item__quantity {
  display: flex;
  justify-content: center;
}

.quantity-controls {
  display: flex;
  align-items: center;
  gap: 8px;
}

.quantity-btn {
  width: 32px;
  height: 32px;
  border: 1px solid #ddd;
  background: white;
  border-radius: 4px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  font-weight: bold;
}

.quantity-btn:hover:not(:disabled) {
  background: #f5f5f5;
}

.quantity-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.quantity-display {
  min-width: 40px;
  text-align: center;
  font-weight: 500;
}

.quantity-static {
  font-weight: 500;
  color: #333;
}

.order-item__subtotal {
  font-size: 16px;
  font-weight: 600;
  color: #333;
  text-align: right;
}

.order-item__actions {
  display: flex;
  justify-content: flex-end;
}

.remove-btn {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 16px;
  padding: 4px;
  border-radius: 4px;
}

.remove-btn:hover {
  background: #ffe8e8;
}

@media (max-width: 768px) {
  .order-item {
    grid-template-columns: 60px 1fr auto;
    gap: 12px;
  }
  
  .order-item--editable {
    grid-template-columns: 60px 1fr auto auto;
  }
  
  .order-item__image {
    width: 60px;
    height: 60px;
  }
  
  .order-item__quantity {
    grid-column: 2;
    grid-row: 2;
    justify-content: flex-start;
  }
  
  .order-item__subtotal {
    grid-column: 3;
    grid-row: 2;
  }
}
</style>
```

### **📁 modules/orders/presentation/components/OrderSummary.vue**

```vue
<template>
  <div class="order-summary">
    <div class="order-summary__header">
      <h3>Order Summary</h3>
    </div>
    
    <div class="order-summary__content">
      <!-- Order Items -->
      <div class="order-items">
        <OrderItem
          v-for="item in order.items"
          :key="item.productId"
          :item="item"
          :editable="editable"
          @update-quantity="$emit('update-item-quantity', $event)"
          @remove-item="$emit('remove-item', $event)"
        />
      </div>
      
      <!-- Cost Breakdown -->
      <div class="cost-breakdown">
        <div class="cost-row">
          <span>Subtotal ({{ order.itemCount }} items)</span>
          <span>{{ formatCurrency(order.subtotal) }}</span>
        </div>
        
        <div class="cost-row">
          <span>Shipping</span>
          <span>{{ formatCurrency(order.shippingCost) }}</span>
        </div>
        
        <div class="cost-row">
          <span>Tax</span>
          <span>{{ formatCurrency(order.taxAmount) }}</span>
        </div>
        
        <div v-if="order.discountAmount > 0" class="cost-row discount">
          <span>Discount</span>
          <span>-{{ formatCurrency(order.discountAmount) }}</span>
        </div>
        
        <div class="cost-row total">
          <span><strong>Total</strong></span>
          <span><strong>{{ formatCurrency(order.total) }}</strong></span>
        </div>
      </div>
      
      <!-- Order Status -->
      <div v-if="showStatus" class="order-status">
        <div class="status-badge" :class="`status-badge--${order.status}`">
          {{ getStatusLabel(order.status) }}
        </div>
        <div class="order-date">
          Ordered on {{ formatDate(order.createdAt) }}
        </div>
      </div>
      
      <!-- Actions -->
      <div v-if="showActions" class="order-actions">
        <button 
          v-if="order.status === 'pending' || order.status === 'confirmed'"
          @click="$emit('cancel-order')"
          class="btn btn--outline"
        >
          Cancel Order
        </button>
        <button 
          v-if="order.status === 'shipped'"
          @click="$emit('track-order')"
          class="btn btn--primary"
        >
          Track Package
        </button>
        <button 
          v-if="order.status === 'delivered'"
          @click="$emit('return-order')"
          class="btn btn--outline"
        >
          Return Items
        </button>
      </div>
    </div>
  </div>
</template>

<script>
import OrderItem from './OrderItem.vue'

export default {
  name: 'OrderSummary',
  components: {
    OrderItem
  },
  props: {
    order: {
      type: Object,
      required: true
    },
    editable: {
      type: Boolean,
      default: false
    },
    showStatus: {
      type: Boolean,
      default: true
    },
    showActions: {
      type: Boolean,
      default: false
    }
  },
  methods: {
    formatCurrency(amount) {
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
      }).format(amount);
    },
    
    formatDate(dateString) {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
    },
    
    getStatusLabel(status) {
      const statusLabels = {
        pending: 'Pending',
        confirmed: 'Confirmed',
        processing: 'Processing',
        shipped: 'Shipped',
        delivered: 'Delivered',
        cancelled: 'Cancelled',
        refunded: 'Refunded'
      };
      return statusLabels[status] || status;
    }
  }
}
</script>

<style scoped>
.order-summary {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  overflow: hidden;
}

.order-summary__header {
  padding: 16px 20px;
  border-bottom: 1px solid #e0e0e0;
  background: #f8f9fa;
}

.order-summary__header h3 {
  margin: 0;
  color: #333;
  font-size: 18px;
}

.order-summary__content {
  padding: 20px;
}

.order-items {
  margin-bottom: 24px;
}

.cost-breakdown {
  border-top: 1px solid #e0e0e0;
  padding-top: 16px;
}

.cost-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  font-size: 14px;
}

.cost-row.discount {
  color: #d32f2f;
}

.cost-row.total {
  border-top: 1px solid #e0e0e0;
  padding-top: 12px;
  margin-top: 12px;
  font-size: 16px;
}

.order-status {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid #e0e0e0;
}

.status-badge {
  padding: 6px 12px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.status-badge--pending {
  background: #fff3cd;
  color: #856404;
}

.status-badge--confirmed {
  background: #d1ecf1;
  color: #0c5460;
}

.status-badge--processing {
  background: #cce7ff;
  color: #004085;
}

.status-badge--shipped {
  background: #d4edda;
  color: #155724;
}

.status-badge--delivered {
  background: #d1ecf1;
  color: #0c5460;
}

.status-badge--cancelled {
  background: #f8d7da;
  color: #721c24;
}

.status-badge--refunded {
  background: #e2e3e5;
  color: #383d41;
}

.order-date {
  color: #666;
  font-size: 14px;
}

.order-actions {
  display: flex;
  gap: 12px;
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid #e0e0e0;
}

.btn {
  padding: 8px 16px;
  border: 1px solid;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s ease;
}

.btn--primary {
  background: #2c5aa0;
  color: white;
  border-color: #2c5aa0;
}

.btn--primary:hover {
  background: #1e3d6f;
}

.btn--outline {
  background: white;
  color: #2c5aa0;
  border-color: #2c5aa0;
}

.btn--outline:hover {
  background: #f8f9fa;
}

@media (max-width: 768px) {
  .order-status {
    flex-direction: column;
    gap: 8px;
    align-items: flex-start;
  }
  
  .order-actions {
    flex-direction: column;
  }
  
  .btn {
    width: 100%;
  }
}
</style>
```

### **📁 modules/orders/presentation/components/CheckoutForm.vue**

```vue
<template>
  <div class="checkout-form">
    <form @submit.prevent="submitOrder">
      <!-- Shipping Address -->
      <div class="form-section">
        <h3>Shipping Address</h3>
        <div class="form-grid">
          <div class="form-group">
            <label for="street">Street Address *</label>
            <input
              id="street"
              v-model="shippingAddress.street"
              type="text"
              required
              placeholder="123 Main St"
            >
          </div>
          
          <div class="form-group">
            <label for="city">City *</label>
            <input
              id="city"
              v-model="shippingAddress.city"
              type="text"
              required
              placeholder="New York"
            >
          </div>
          
          <div class="form-group">
            <label for="state">State *</label>
            <select
              id="state"
              v-model="shippingAddress.state"
              required
            >
              <option value="">Select State</option>
              <option v-for="state in states" :key="state" :value="state">
                {{ state }}
              </option>
            </select>
          </div>
          
          <div class="form-group">
            <label for="zipCode">ZIP Code *</label>
            <input
              id="zipCode"
              v-model="shippingAddress.zipCode"
              type="text"
              required
              placeholder="10001"
              pattern="\d{5}(-\d{4})?"
            >
          </div>
        </div>
      </div>

      <!-- Shipping Method -->
      <div class="form-section">
        <h3>Shipping Method</h3>
        <div class="shipping-options">
          <label
            v-for="option in shippingOptions"
            :key="option.value"
            class="shipping-option"
            :class="{ 'shipping-option--selected': shippingMethod === option.value }"
          >
            <input
              type="radio"
              :value="option.value"
              v-model="shippingMethod"
              class="shipping-radio"
            >
            <div class="shipping-option__content">
              <span class="shipping-option__name">{{ option.name }}</span>
              <span class="shipping-option__price">{{ formatCurrency(option.cost) }}</span>
              <span class="shipping-option__time">{{ option.estimatedDays }}</span>
            </div>
          </label>
        </div>
      </div>

      <!-- Payment Method -->
      <div class="form-section">
        <h3>Payment Method</h3>
        <div class="payment-methods">
          <label
            v-for="method in paymentMethods"
            :key="method.value"
            class="payment-method"
            :class="{ 'payment-method--selected': paymentMethod === method.value }"
          >
            <input
              type="radio"
              :value="method.value"
              v-model="paymentMethod"
              class="payment-radio"
            >
            <span class="payment-method__name">{{ method.name }}</span>
            <span class="payment-method__icon">{{ method.icon }}</span>
          </label>
        </div>

        <!-- Credit Card Form -->
        <div v-if="paymentMethod === 'credit_card'" class="credit-card-form">
          <div class="form-grid">
            <div class="form-group">
              <label for="cardNumber">Card Number *</label>
              <input
                id="cardNumber"
                v-model="paymentDetails.cardNumber"
                type="text"
                placeholder="1234 5678 9012 3456"
                required
              >
            </div>
            
            <div class="form-group">
              <label for="expiryDate">Expiry Date *</label>
              <input
                id="expiryDate"
                v-model="paymentDetails.expiryDate"
                type="text"
                placeholder="MM/YY"
                required
              >
            </div>
            
            <div class="form-group">
              <label for="cvv">CVV *</label>
              <input
                id="cvv"
                v-model="paymentDetails.cvv"
                type="text"
                placeholder="123"
                required
              >
            </div>
            
            <div class="form-group">
              <label for="cardholder">Cardholder Name *</label>
              <input
                id="cardholder"
                v-model="paymentDetails.cardholder"
                type="text"
                placeholder="John Doe"
                required
              >
            </div>
          </div>
        </div>

        <!-- PayPal Info -->
        <div v-if="paymentMethod === 'paypal'" class="paypal-info">
          <p>You will be redirected to PayPal to complete your payment.</p>
        </div>
      </div>

      <!-- Order Notes -->
      <div class="form-section">
        <h3>Order Notes (Optional)</h3>
        <textarea
          v-model="orderNotes"
          placeholder="Add any special instructions for your order..."
          rows="3"
          class="notes-textarea"
        ></textarea>
      </div>

      <!-- Submit Button -->
      <div class="form-actions">
        <button
          type="submit"
          :disabled="processing || !isFormValid"
          class="submit-btn"
          :class="{ 'submit-btn--processing': processing }"
        >
          <span v-if="processing" class="processing-spinner"></span>
          {{ processing ? 'Processing...' : `Place Order - ${formatCurrency(total)}` }}
        </button>
        
        <p class="security-note">
          🔒 Your payment information is secure and encrypted
        </p>
      </div>
    </form>
  </div>
</template>

<script>
export default {
  name: 'CheckoutForm',
  props: {
    total: {
      type: Number,
      required: true
    },
    processing: {
      type: Boolean,
      default: false
    }
  },
  data() {
    return {
      shippingAddress: {
        street: '',
        city: '',
        state: '',
        zipCode: '',
        country: 'US'
      },
      shippingMethod: 'standard',
      paymentMethod: 'credit_card',
      paymentDetails: {
        cardNumber: '',
        expiryDate: '',
        cvv: '',
        cardholder: ''
      },
      orderNotes: '',
      states: [
        'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA',
        'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD',
        'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ',
        'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC',
        'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY'
      ],
      shippingOptions: [
        { value: 'standard', name: 'Standard Shipping', cost: 5.99, estimatedDays: '3-5 business days' },
        { value: 'express', name: 'Express Shipping', cost: 12.99, estimatedDays: '2 business days' },
        { value: 'overnight', name: 'Overnight Shipping', cost: 24.99, estimatedDays: '1 business day' }
      ],
      paymentMethods: [
        { value: 'credit_card', name: 'Credit Card', icon: '💳' },
        { value: 'paypal', name: 'PayPal', icon: '🔵' },
        { value: 'debit_card', name: 'Debit Card', icon: '💳' }
      ]
    }
  },
  computed: {
    isFormValid() {
      return (
        this.shippingAddress.street &&
        this.shippingAddress.city &&
        this.shippingAddress.state &&
        this.shippingAddress.zipCode &&
        this.paymentMethod
      )
    }
  },
  methods: {
    formatCurrency(amount) {
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
      }).format(amount)
    },
    
    submitOrder() {
      const orderData = {
        shippingAddress: { ...this.shippingAddress },
        shippingMethod: this.shippingMethod,
        paymentMethod: this.paymentMethod,
        paymentDetails: { ...this.paymentDetails },
        notes: this.orderNotes
      }
      
      this.$emit('submit-order', orderData)
    }
  }
}
</script>

<style scoped>
.checkout-form {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 24px;
}

.form-section {
  margin-bottom: 32px;
  padding-bottom: 24px;
  border-bottom: 1px solid #f0f0f0;
}

.form-section:last-child {
  border-bottom: none;
  margin-bottom: 0;
}

.form-section h3 {
  margin: 0 0 16px 0;
  color: #333;
  font-size: 18px;
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.form-group {
  display: flex;
  flex-direction: column;
}

.form-group label {
  margin-bottom: 8px;
  font-weight: 500;
  color: #333;
  font-size: 14px;
}

.form-group input,
.form-group select,
.form-group textarea {
  padding: 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  transition: border-color 0.2s ease;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #2c5aa0;
}

.shipping-options {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.shipping-option {
  display: flex;
  align-items: center;
  padding: 16px;
  border: 2px solid #e0e0e0;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.shipping-option--selected {
  border-color: #2c5aa0;
  background: #f8f9fa;
}

.shipping-radio {
  margin-right: 12px;
}

.shipping-option__content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex: 1;
}

.shipping-option__name {
  font-weight: 500;
  color: #333;
}

.shipping-option__price {
  font-weight: 600;
  color: #2c5aa0;
}

.shipping-option__time {
  color: #666;
  font-size: 14px;
}

.payment-methods {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}

.payment-method {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 16px;
  border: 2px solid #e0e0e0;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  text-align: center;
}

.payment-method--selected {
  border-color: #2c5aa0;
  background: #f8f9fa;
}

.payment-radio {
  margin-bottom: 8px;
}

.payment-method__name {
  font-weight: 500;
  color: #333;
  margin-bottom: 4px;
}

.payment-method__icon {
  font-size: 20px;
}

.credit-card-form,
.paypal-info {
  margin-top: 20px;
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
}

.paypal-info p {
  margin: 0;
  color: #666;
  text-align: center;
}

.notes-textarea {
  width: 100%;
  padding: 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  resize: vertical;
}

.notes-textarea:focus {
  outline: none;
  border-color: #2c5aa0;
}

.form-actions {
  text-align: center;
  margin-top: 32px;
}

.submit-btn {
  width: 100%;
  padding: 16px;
  background: #2c5aa0;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 18px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
  position: relative;
}

.submit-btn:hover:not(:disabled) {
  background: #1e3d6f;
}

.submit-btn:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.submit-btn--processing {
  background: #1e3d6f;
}

.processing-spinner {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid transparent;
  border-top: 2px solid white;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-right: 8px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.security-note {
  margin: 12px 0 0 0;
  color: #666;
  font-size: 14px;
  text-align: center;
}

@media (max-width: 768px) {
  .checkout-form {
    padding: 16px;
  }
  
  .form-grid {
    grid-template-columns: 1fr;
  }
  
  .payment-methods {
    grid-template-columns: 1fr;
  }
  
  .shipping-option__content {
    flex-direction: column;
    gap: 4px;
    align-items: flex-start;
  }
}
</style>
```

### **📁 modules/orders/presentation/views/CheckoutView.vue**

```vue
<template>
  <div class="checkout-view">
    <div class="checkout-view__header">
      <h1>Checkout</h1>
      <div class="checkout-steps">
        <div class="step" :class="{ 'step--active': currentStep === 1, 'step--completed': currentStep > 1 }">
          <span class="step-number">1</span>
          <span class="step-label">Shipping</span>
        </div>
        <div class="step" :class="{ 'step--active': currentStep === 2, 'step--completed': currentStep > 2 }">
          <span class="step-number">2</span>
          <span class="step-label">Payment</span>
        </div>
        <div class="step" :class="{ 'step--active': currentStep === 3 }">
          <span class="step-number">3</span>
          <span class="step-label">Confirmation</span>
        </div>
      </div>
    </div>

    <div class="checkout-view__content">
      <!-- Step 1: Review Order -->
      <div v-if="currentStep === 1" class="checkout-step">
        <div class="step-content">
          <div class="step-header">
            <h2>Review Your Order</h2>
            <p>Please review your items before proceeding to payment</p>
          </div>
          
          <OrderSummary
            :order="currentOrder"
            :editable="true"
            :show-status="false"
            :show-actions="false"
            @update-item-quantity="updateItemQuantity"
            @remove-item="removeItem"
          />
          
          <div class="step-actions">
            <button @click="$router.back()" class="btn btn--outline">
              Continue Shopping
            </button>
            <button @click="currentStep = 2" class="btn btn--primary">
              Proceed to Payment
            </button>
          </div>
        </div>
      </div>

      <!-- Step 2: Payment -->
      <div v-else-if="currentStep === 2" class="checkout-step">
        <div class="step-content">
          <div class="step-header">
            <h2>Payment Information</h2>
            <p>Enter your shipping and payment details</p>
          </div>
          
          <div class="checkout-layout">
            <div class="checkout-form-container">
              <CheckoutForm
                :total="currentOrder.total"
                :processing="processing"
                @submit-order="processOrder"
              />
            </div>
            
            <div class="order-summary-container">
              <OrderSummary
                :order="currentOrder"
                :editable="false"
                :show-status="false"
                :show-actions="false"
              />
            </div>
          </div>
        </div>
      </div>

      <!-- Step 3: Confirmation -->
      <div v-else-if="currentStep === 3" class="checkout-step">
        <div class="confirmation-content">
          <div class="confirmation-header">
            <div class="success-icon">✅</div>
            <h2>Order Confirmed!</h2>
            <p class="confirmation-message">
              Thank you for your order. Your order number is 
              <strong>{{ orderResult.orderId }}</strong>
            </p>
          </div>
          
          <div class="confirmation-details">
            <div class="detail-card">
              <h3>Order Summary</h3>
              <OrderSummary
                :order="currentOrder"
                :editable="false"
                :show-status="true"
                :show-actions="false"
              />
            </div>
            
            <div class="detail-card">
              <h3>What's Next?</h3>
              <div class="next-steps">
                <div class="next-step">
                  <span class="step-icon">📧</span>
                  <div class="step-info">
                    <strong>Order Confirmation</strong>
                    <p>We've sent a confirmation email to your inbox</p>
                  </div>
                </div>
                <div class="next-step">
                  <span class="step-icon">📦</span>
                  <div class="step-info">
                    <strong>Order Processing</strong>
                    <p>Your order will be processed within 24 hours</p>
                  </div>
                </div>
                <div class="next-step">
                  <span class="step-icon">🚚</span>
                  <div class="step-info">
                    <strong>Shipping Updates</strong>
                    <p>You'll receive tracking information once shipped</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <div class="confirmation-actions">
            <button @click="continueShopping" class="btn btn--primary">
              Continue Shopping
            </button>
            <button @click="viewOrderHistory" class="btn btn--outline">
              View Order History
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Loading Overlay -->
    <div v-if="processing" class="loading-overlay">
      <div class="loading-content">
        <div class="loading-spinner-large"></div>
        <p>Processing your order...</p>
      </div>
    </div>
  </div>
</template>

<script>
import { CreateOrderUseCase } from '../../application/use-cases/create-order-use-case.js'
import { ProcessPaymentUseCase } from '../../application/use-cases/process-payment-use-case.js'
import { OrderRepository } from '../../infrastructure/persistence/order-repository.js'
import { PaymentAdapter } from '../../infrastructure/persistence/payment-adapter.js'
import OrderSummary from '../components/OrderSummary.vue'
import CheckoutForm from '../components/CheckoutForm.vue'

export default {
  name: 'CheckoutView',
  components: {
    OrderSummary,
    CheckoutForm
  },
  data() {
    return {
      currentStep: 1,
      processing: false,
      currentOrder: {
        items: [],
        subtotal: 0,
        shippingCost: 0,
        taxAmount: 0,
        discountAmount: 0,
        total: 0,
        itemCount: 0,
        status: 'pending',
        createdAt: new Date()
      },
      orderResult: null,
      cartItems: []
    }
  },
  async created() {
    await this.loadCartItems()
    this.calculateOrderTotals()
  },
  methods: {
    async loadCartItems() {
      // Load cart items from storage or cart module
      const cartData = localStorage.getItem('shopping_cart')
      this.cartItems = cartData ? JSON.parse(cartData) : []
      
      // Transform cart items to order items
      this.currentOrder.items = this.cartItems.map(item => ({
        productId: item.id,
        productName: item.name,
        unitPrice: item.price,
        quantity: item.quantity,
        imageUrl: item.imageUrl,
        subtotal: item.price * item.quantity
      }))
    },
    
    calculateOrderTotals() {
      this.currentOrder.subtotal = this.currentOrder.items.reduce(
        (sum, item) => sum + item.subtotal, 0
      )
      this.currentOrder.shippingCost = 5.99
      this.currentOrder.taxAmount = this.currentOrder.subtotal * 0.08
      this.currentOrder.total = this.currentOrder.subtotal + 
                               this.currentOrder.shippingCost + 
                               this.currentOrder.taxAmount
      this.currentOrder.itemCount = this.currentOrder.items.reduce(
        (sum, item) => sum + item.quantity, 0
      )
    },
    
    updateItemQuantity({ productId, quantity }) {
      const item = this.currentOrder.items.find(item => item.productId === productId)
      if (item) {
        item.quantity = quantity
        item.subtotal = item.unitPrice * quantity
        this.calculateOrderTotals()
      }
    },
    
    removeItem(productId) {
      this.currentOrder.items = this.currentOrder.items.filter(
        item => item.productId !== productId
      )
      this.calculateOrderTotals()
    },
    
    async processOrder(orderData) {
      this.processing = true
      
      try {
        // Create order
        const orderRepository = new OrderRepository()
        const createOrderUseCase = new CreateOrderUseCase(orderRepository)
        
        const orderCommand = {
          customerId: 'user_123', // In real app, get from auth
          shippingAddress: orderData.shippingAddress,
          shippingMethod: orderData.shippingMethod,
          items: this.currentOrder.items.map(item => ({
            productId: item.productId,
            productName: item.productName,
            unitPrice: item.unitPrice,
            quantity: item.quantity,
            imageUrl: item.imageUrl
          }))
        }
        
        const order = await createOrderUseCase.execute(orderCommand)
        
        // Process payment
        const paymentAdapter = new PaymentAdapter()
        const processPaymentUseCase = new ProcessPaymentUseCase(
          orderRepository,
          paymentAdapter
        )
        
        const paymentCommand = {
          orderId: order.id,
          paymentMethod: orderData.paymentMethod,
          paymentDetails: orderData.paymentDetails,
          amount: order.total
        }
        
        const paymentResult = await processPaymentUseCase.execute(paymentCommand)
        
        if (paymentResult.success) {
          this.orderResult = {
            orderId: order.id,
            status: paymentResult.orderStatus,
            transactionId: paymentResult.transactionId
          }
          
          // Clear cart
          localStorage.removeItem('shopping_cart')
          
          // Move to confirmation step
          this.currentStep = 3
        } else {
          throw new Error(paymentResult.message)
        }
        
      } catch (error) {
        console.error('Order processing failed:', error)
        this.$notify({
          title: 'Order Failed',
          message: error.message,
          type: 'error'
        })
      } finally {
        this.processing = false
      }
    },
    
    continueShopping() {
      this.$router.push('/products')
    },
    
    viewOrderHistory() {
      this.$router.push('/orders')
    }
  }
}
</script>

<style scoped>
Here's the continuation and completion of the Orders module Vue.js 2 implementation:

### **📁 modules/orders/presentation/views/CheckoutView.vue** (continued)

```vue
<style scoped>
.checkout-view {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.checkout-view__header {
  text-align: center;
  margin-bottom: 40px;
}

.checkout-view__header h1 {
  margin: 0 0 24px 0;
  color: #333;
  font-size: 2.5rem;
}

.checkout-steps {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 40px;
}

.step {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  color: #666;
}

.step-number {
  width: 32px;
  height: 32px;
  border: 2px solid #e0e0e0;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  font-size: 14px;
}

.step-label {
  font-size: 14px;
  font-weight: 500;
}

.step--active .step-number {
  border-color: #2c5aa0;
  background: #2c5aa0;
  color: white;
}

.step--active .step-label {
  color: #2c5aa0;
}

.step--completed .step-number {
  border-color: #2c5aa0;
  background: #2c5aa0;
  color: white;
}

.step--completed .step-label {
  color: #2c5aa0;
}

.checkout-step {
  min-height: 500px;
}

.step-content {
  max-width: 800px;
  margin: 0 auto;
}

.step-header {
  text-align: center;
  margin-bottom: 32px;
}

.step-header h2 {
  margin: 0 0 8px 0;
  color: #333;
  font-size: 2rem;
}

.step-header p {
  margin: 0;
  color: #666;
  font-size: 1.1rem;
}

.step-actions {
  display: flex;
  justify-content: space-between;
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid #e0e0e0;
}

.checkout-layout {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 32px;
  align-items: start;
}

.checkout-form-container {
  background: white;
  border-radius: 8px;
}

.order-summary-container {
  position: sticky;
  top: 20px;
}

.confirmation-content {
  max-width: 600px;
  margin: 0 auto;
  text-align: center;
}

.confirmation-header {
  margin-bottom: 48px;
}

.success-icon {
  font-size: 64px;
  margin-bottom: 24px;
}

.confirmation-header h2 {
  margin: 0 0 16px 0;
  color: #2d5016;
  font-size: 2.5rem;
}

.confirmation-message {
  font-size: 1.2rem;
  color: #666;
  line-height: 1.6;
}

.confirmation-details {
  display: grid;
  gap: 24px;
  margin-bottom: 48px;
}

.detail-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 24px;
  text-align: left;
}

.detail-card h3 {
  margin: 0 0 20px 0;
  color: #333;
  font-size: 1.3rem;
  border-bottom: 1px solid #e0e0e0;
  padding-bottom: 12px;
}

.next-steps {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.next-step {
  display: flex;
  align-items: flex-start;
  gap: 16px;
}

.step-icon {
  font-size: 24px;
  flex-shrink: 0;
}

.step-info {
  flex: 1;
  text-align: left;
}

.step-info strong {
  display: block;
  margin-bottom: 4px;
  color: #333;
}

.step-info p {
  margin: 0;
  color: #666;
  font-size: 14px;
}

.confirmation-actions {
  display: flex;
  gap: 16px;
  justify-content: center;
}

.btn {
  padding: 12px 24px;
  border: 1px solid;
  border-radius: 6px;
  cursor: pointer;
  font-size: 16px;
  font-weight: 500;
  transition: all 0.2s ease;
  text-decoration: none;
  display: inline-block;
}

.btn--primary {
  background: #2c5aa0;
  color: white;
  border-color: #2c5aa0;
}

.btn--primary:hover {
  background: #1e3d6f;
}

.btn--outline {
  background: white;
  color: #2c5aa0;
  border-color: #2c5aa0;
}

.btn--outline:hover {
  background: #f8f9fa;
}

.loading-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.loading-content {
  background: white;
  padding: 40px;
  border-radius: 8px;
  text-align: center;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
}

.loading-spinner-large {
  width: 48px;
  height: 48px;
  border: 4px solid #f3f3f3;
  border-top: 4px solid #2c5aa0;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 16px;
}

.loading-content p {
  margin: 0;
  color: #333;
  font-size: 16px;
  font-weight: 500;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

@media (max-width: 768px) {
  .checkout-view {
    padding: 16px;
  }
  
  .checkout-steps {
    gap: 20px;
  }
  
  .step-label {
    font-size: 12px;
  }
  
  .checkout-layout {
    grid-template-columns: 1fr;
  }
  
  .order-summary-container {
    position: static;
  }
  
  .step-actions {
    flex-direction: column;
    gap: 12px;
  }
  
  .confirmation-actions {
    flex-direction: column;
  }
  
  .btn {
    width: 100%;
  }
}
</style>
```

### **📁 modules/orders/presentation/views/OrderHistoryView.vue**

```vue
<template>
  <div class="order-history-view">
    <div class="order-history-view__header">
      <h1>Order History</h1>
      <p>View and manage your past orders</p>
    </div>

    <div class="order-history-view__content">
      <!-- Filters -->
      <div class="filters-section">
        <div class="filter-group">
          <label for="status-filter">Filter by Status:</label>
          <select id="status-filter" v-model="statusFilter" class="filter-select">
            <option value="">All Orders</option>
            <option value="pending">Pending</option>
            <option value="confirmed">Confirmed</option>
            <option value="processing">Processing</option>
            <option value="shipped">Shipped</option>
            <option value="delivered">Delivered</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>
        
        <div class="filter-group">
          <label for="date-filter">Filter by Date:</label>
          <select id="date-filter" v-model="dateFilter" class="filter-select">
            <option value="all">All Time</option>
            <option value="30">Last 30 Days</option>
            <option value="90">Last 90 Days</option>
            <option value="365">Last Year</option>
          </select>
        </div>
      </div>

      <!-- Loading State -->
      <div v-if="loading" class="loading-state">
        <div class="loading-spinner"></div>
        <p>Loading your orders...</p>
      </div>

      <!-- Empty State -->
      <div v-else-if="filteredOrders.length === 0" class="empty-state">
        <div class="empty-icon">📦</div>
        <h3>No orders found</h3>
        <p v-if="hasFilters">
          Try adjusting your filters to see more results
        </p>
        <p v-else>
          You haven't placed any orders yet
        </p>
        <button @click="$router.push('/products')" class="btn btn--primary">
          Start Shopping
        </button>
      </div>

      <!-- Orders List -->
      <div v-else class="orders-list">
        <div 
          v-for="order in paginatedOrders" 
          :key="order.id"
          class="order-card"
        >
          <div class="order-card__header">
            <div class="order-info">
              <h3 class="order-number">Order #{{ order.id }}</h3>
              <div class="order-date">
                {{ formatDate(order.createdAt) }}
              </div>
            </div>
            <div class="order-status">
              <span class="status-badge" :class="`status-badge--${order.status}`">
                {{ getStatusLabel(order.status) }}
              </span>
            </div>
          </div>

          <div class="order-card__content">
            <div class="order-items-preview">
              <div 
                v-for="item in order.items.slice(0, 3)" 
                :key="item.productId"
                class="preview-item"
              >
                <img 
                  :src="item.imageUrl || '/placeholder-product.jpg'" 
                  :alt="item.productName"
                  class="preview-image"
                >
                <div class="preview-details">
                  <div class="preview-name">{{ item.productName }}</div>
                  <div class="preview-quantity">Qty: {{ item.quantity }}</div>
                </div>
              </div>
              <div v-if="order.items.length > 3" class="more-items">
                +{{ order.items.length - 3 }} more items
              </div>
            </div>

            <div class="order-summary">
              <div class="summary-item">
                <span>Items:</span>
                <span>{{ order.itemCount }}</span>
              </div>
              <div class="summary-item">
                <span>Total:</span>
                <span class="order-total">{{ formatCurrency(order.total) }}</span>
              </div>
            </div>
          </div>

          <div class="order-card__actions">
            <button 
              @click="viewOrderDetails(order)"
              class="btn btn--outline btn--sm"
            >
              View Details
            </button>
            <button 
              v-if="order.status === 'shipped' && order.trackingNumber"
              @click="trackOrder(order)"
              class="btn btn--outline btn--sm"
            >
              Track Package
            </button>
            <button 
              v-if="order.status === 'delivered'"
              @click="startReturn(order)"
              class="btn btn--outline btn--sm"
            >
              Return Items
            </button>
            <button 
              v-if="order.status === 'pending' || order.status === 'confirmed'"
              @click="cancelOrder(order)"
              class="btn btn--outline btn--sm btn--danger"
            >
              Cancel Order
            </button>
          </div>
        </div>
      </div>

      <!-- Pagination -->
      <div v-if="filteredOrders.length > itemsPerPage" class="pagination">
        <button 
          :disabled="currentPage === 1" 
          @click="currentPage--"
          class="pagination-btn"
        >
          Previous
        </button>
        
        <span class="pagination-info">
          Page {{ currentPage }} of {{ totalPages }}
        </span>
        
        <button 
          :disabled="currentPage === totalPages" 
          @click="currentPage++"
          class="pagination-btn"
        >
          Next
        </button>
      </div>
    </div>

    <!-- Order Details Modal -->
    <div v-if="selectedOrder" class="modal-overlay" @click="closeModal">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h2>Order Details - #{{ selectedOrder.id }}</h2>
          <button class="close-btn" @click="closeModal">×</button>
        </div>
        
        <div class="modal-body">
          <OrderSummary
            :order="selectedOrder"
            :editable="false"
            :show-status="true"
            :show-actions="true"
            @cancel-order="handleCancelOrder"
            @track-order="handleTrackOrder"
            @return-order="handleReturnOrder"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { OrderRepository } from '../../infrastructure/persistence/order-repository.js'
import { CancelOrderUseCase } from '../../application/use-cases/cancel-order-use-case.js'
import OrderSummary from '../components/OrderSummary.vue'

export default {
  name: 'OrderHistoryView',
  components: {
    OrderSummary
  },
  data() {
    return {
      loading: false,
      orders: [],
      selectedOrder: null,
      statusFilter: '',
      dateFilter: 'all',
      currentPage: 1,
      itemsPerPage: 10
    }
  },
  computed: {
    filteredOrders() {
      let filtered = this.orders
      
      // Filter by status
      if (this.statusFilter) {
        filtered = filtered.filter(order => order.status === this.statusFilter)
      }
      
      // Filter by date
      if (this.dateFilter !== 'all') {
        const daysAgo = parseInt(this.dateFilter)
        const cutoffDate = new Date()
        cutoffDate.setDate(cutoffDate.getDate() - daysAgo)
        
        filtered = filtered.filter(order => new Date(order.createdAt) >= cutoffDate)
      }
      
      return filtered
    },
    
    paginatedOrders() {
      const startIndex = (this.currentPage - 1) * this.itemsPerPage
      const endIndex = startIndex + this.itemsPerPage
      return this.filteredOrders.slice(startIndex, endIndex)
    },
    
    totalPages() {
      return Math.ceil(this.filteredOrders.length / this.itemsPerPage)
    },
    
    hasFilters() {
      return this.statusFilter || this.dateFilter !== 'all'
    }
  },
  watch: {
    statusFilter() {
      this.currentPage = 1
    },
    dateFilter() {
      this.currentPage = 1
    }
  },
  async created() {
    await this.loadOrders()
  },
  methods: {
    async loadOrders() {
      this.loading = true
      try {
        const orderRepository = new OrderRepository()
        // In a real app, you'd get customerId from authentication
        const customerId = 'user_123'
        this.orders = await orderRepository.findByCustomerId(customerId)
      } catch (error) {
        console.error('Error loading orders:', error)
        this.$notify({
          title: 'Error',
          message: 'Failed to load orders',
          type: 'error'
        })
      } finally {
        this.loading = false
      }
    },
    
    formatCurrency(amount) {
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
      }).format(amount)
    },
    
    formatDate(dateString) {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      })
    },
    
    getStatusLabel(status) {
      const statusLabels = {
        pending: 'Pending',
        confirmed: 'Confirmed',
        processing: 'Processing',
        shipped: 'Shipped',
        delivered: 'Delivered',
        cancelled: 'Cancelled',
        refunded: 'Refunded'
      }
      return statusLabels[status] || status
    },
    
    viewOrderDetails(order) {
      this.selectedOrder = order
    },
    
    closeModal() {
      this.selectedOrder = null
    },
    
    async cancelOrder(order) {
      if (!confirm('Are you sure you want to cancel this order?')) {
        return
      }
      
      try {
        const orderRepository = new OrderRepository()
        const cancelOrderUseCase = new CancelOrderUseCase(orderRepository)
        
        await cancelOrderUseCase.execute({
          orderId: order.id,
          reason: 'Cancelled by customer'
        })
        
        this.$notify({
          title: 'Order Cancelled',
          message: 'Your order has been cancelled successfully',
          type: 'success'
        })
        
        // Reload orders to reflect changes
        await this.loadOrders()
        this.closeModal()
        
      } catch (error) {
        console.error('Error cancelling order:', error)
        this.$notify({
          title: 'Cancellation Failed',
          message: error.message,
          type: 'error'
        })
      }
    },
    
    trackOrder(order) {
      if (order.trackingNumber) {
        // In a real app, this would open tracking in a new window
        const trackingUrl = `https://tracking.example.com/track/${order.trackingNumber}`
        window.open(trackingUrl, '_blank')
      } else {
        this.$notify({
          title: 'Tracking Unavailable',
          message: 'Tracking information is not yet available for this order',
          type: 'warning'
        })
      }
    },
    
    startReturn(order) {
      this.$notify({
        title: 'Return Process',
        message: 'Return process would start here',
        type: 'info'
      })
    },
    
    handleCancelOrder() {
      if (this.selectedOrder) {
        this.cancelOrder(this.selectedOrder)
      }
    },
    
    handleTrackOrder() {
      if (this.selectedOrder) {
        this.trackOrder(this.selectedOrder)
      }
    },
    
    handleReturnOrder() {
      if (this.selectedOrder) {
        this.startReturn(this.selectedOrder)
      }
    }
  }
}
</script>

<style scoped>
.order-history-view {
  max-width: 1000px;
  margin: 0 auto;
  padding: 20px;
}

.order-history-view__header {
  text-align: center;
  margin-bottom: 40px;
}

.order-history-view__header h1 {
  margin: 0 0 8px 0;
  color: #333;
  font-size: 2.5rem;
}

.order-history-view__header p {
  margin: 0;
  color: #666;
  font-size: 1.1rem;
}

.filters-section {
  display: flex;
  gap: 20px;
  margin-bottom: 24px;
  padding: 20px;
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.filter-group label {
  font-weight: 500;
  color: #333;
  font-size: 14px;
}

.filter-select {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  min-width: 150px;
}

.loading-state {
  text-align: center;
  padding: 60px 20px;
  color: #666;
}

.loading-spinner {
  border: 3px solid #f3f3f3;
  border-top: 3px solid #2c5aa0;
  border-radius: 50%;
  width: 40px;
  height: 40px;
  animation: spin 1s linear infinite;
  margin: 0 auto 16px;
}

.empty-state {
  text-align: center;
  padding: 60px 20px;
  color: #666;
}

.empty-icon {
  font-size: 64px;
  margin-bottom: 16px;
}

.empty-state h3 {
  margin: 0 0 8px 0;
  color: #333;
}

.empty-state p {
  margin: 0 0 24px 0;
}

.orders-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.order-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  overflow: hidden;
  transition: box-shadow 0.2s ease;
}

.order-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.order-card__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  background: #f8f9fa;
  border-bottom: 1px solid #e0e0e0;
}

.order-info {
  flex: 1;
}

.order-number {
  margin: 0 0 4px 0;
  font-size: 18px;
  color: #333;
}

.order-date {
  color: #666;
  font-size: 14px;
}

.order-status {
  flex-shrink: 0;
}

.status-badge {
  padding: 6px 12px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.status-badge--pending {
  background: #fff3cd;
  color: #856404;
}

.status-badge--confirmed {
  background: #d1ecf1;
  color: #0c5460;
}

.status-badge--processing {
  background: #cce7ff;
  color: #004085;
}

.status-badge--shipped {
  background: #d4edda;
  color: #155724;
}

.status-badge--delivered {
  background: #d1ecf1;
  color: #0c5460;
}

.status-badge--cancelled {
  background: #f8d7da;
  color: #721c24;
}

.status-badge--refunded {
  background: #e2e3e5;
  color: #383d41;
}

.order-card__content {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 24px;
  padding: 20px;
}

.order-items-preview {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.preview-item {
  display: flex;
  align-items: center;
  gap: 12px;
}

.preview-image {
  width: 50px;
  height: 50px;
  border-radius: 4px;
  object-fit: cover;
}

.preview-details {
  flex: 1;
}

.preview-name {
  font-weight: 500;
  color: #333;
  margin-bottom: 2px;
}

.preview-quantity {
  font-size: 12px;
  color: #666;
}

.more-items {
  color: #666;
  font-size: 14px;
  font-style: italic;
  margin-top: 8px;
}

.order-summary {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.summary-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 14px;
}

.order-total {
  font-weight: 600;
  color: #2c5aa0;
  font-size: 16px;
}

.order-card__actions {
  display: flex;
  gap: 8px;
  padding: 16px 20px;
  background: #f8f9fa;
  border-top: 1px solid #e0e0e0;
}

.btn--sm {
  padding: 6px 12px;
  font-size: 12px;
}

.btn--danger {
  color: #d32f2f;
  border-color: #d32f2f;
}

.btn--danger:hover {
  background: #ffe8e8;
}

.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 16px;
  margin-top: 32px;
  padding: 20px 0;
}

.pagination-btn {
  padding: 8px 16px;
  border: 1px solid #ddd;
  background: white;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.pagination-btn:hover:not(:disabled) {
  background: #f5f5f5;
}

.pagination-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.pagination-info {
  color: #666;
  font-size: 14px;
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: white;
  border-radius: 8px;
  width: 90%;
  max-width: 800px;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid #e0e0e0;
}

.modal-header h2 {
  margin: 0;
  color: #333;
}

.close-btn {
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
  color: #666;
  padding: 4px;
}

.close-btn:hover {
  color: #333;
}

.modal-body {
  padding: 24px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

@media (max-width: 768px) {
  .order-history-view {
    padding: 16px;
  }
  
  .filters-section {
    flex-direction: column;
    gap: 16px;
  }
  
  .order-card__header {
    flex-direction: column;
    gap: 12px;
    align-items: flex-start;
  }
  
  .order-card__content {
    grid-template-columns: 1fr;
    gap: 16px;
  }
  
  .order-card__actions {
    flex-wrap: wrap;
  }
  
  .modal-content {
    width: 95%;
  }
}
</style>
```

## 🔧 **Vue 2 App Integration**

### **Update main.js**

```javascript
import Vue from 'vue'
import App from './App.vue'
import router from './router'

// Import orders components
import OrderHistoryView from './modules/orders/presentation/views/OrderHistoryView.vue'
import CheckoutView from './modules/orders/presentation/views/CheckoutView.vue'

// Register global components
Vue.component('OrderSummary', () => import('./modules/orders/presentation/components/OrderSummary.vue'))
Vue.component('OrderItem', () => import('./modules/orders/presentation/components/OrderItem.vue'))
Vue.component('CheckoutForm', () => import('./modules/orders/presentation/components/CheckoutForm.vue'))

// Vue notification plugin
Vue.prototype.$notify = function(options) {
  // Implementation with your preferred notification library
  if (options.type === 'error') {
    alert(`Error: ${options.message}`)
  } else {
    console.log('Notification:', options)
  }
}

new Vue({
  router,
  render: h => h(App)
}).$mount('#app')
```

### **Update router/index.js**

```javascript
import Vue from 'vue'
import Router from 'vue-router'
import ProductListView from '../modules/catalog/presentation/views/ProductListView.vue'
import ProductDetailView from '../modules/catalog/presentation/views/ProductDetailView.vue'
import OrderHistoryView from '../modules/orders/presentation/views/OrderHistoryView.vue'
import CheckoutView from '../modules/orders/presentation/views/CheckoutView.vue'

Vue.use(Router)

export default new Router({
  mode: 'history',
  routes: [
    {
      path: '/products',
      name: 'products',
      component: ProductListView
    },
    {
      path: '/products/:id',
      name: 'product-detail',
      component: ProductDetailView,
      props: true
    },
    {
      path: '/checkout',
      name: 'checkout',
      component: CheckoutView
    },
    {
      path: '/orders',
      name: 'orders',
      component: OrderHistoryView
    },
    {
      path: '/',
      redirect: '/products'
    }
  ]
})
```

## 🎯 **Complete Orders Module Features**

This implementation provides:

1. **Complete Order Management** - Create, view, cancel orders
2. **Payment Processing** - Multiple payment methods with simulated gateway
3. **Order Tracking** - Status updates and tracking information
4. **Responsive Design** - Mobile-friendly interfaces
5. **Domain-Driven Architecture** - Clean separation of concerns
6. **Vue.js 2 Compatibility** - Using Options API and Vue 2 patterns
7. **Professional UI/UX** - Loading states, error handling, and smooth transitions

The Orders module integrates seamlessly with the Catalog module and provides a complete e-commerce order management system following DDD principles with Vue.js 2.