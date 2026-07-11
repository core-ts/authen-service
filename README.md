# authen-service

A lightweight, framework-agnostic, database-independent authentication library for Node.js and TypeScript.

`authen-service` provides the business logic for user authentication without depending on Express, NestJS, Passport, Prisma, TypeORM, or any specific database.

It is designed for enterprise applications that require complete control over authentication while remaining independent of infrastructure.

---

## Features

- Database independent
- Framework independent
- TypeScript first
- Generic user ID support
- Password verification
- Account locking
- Failed login tracking
- Automatic unlock
- Password expiration
- Access date validation
- Access time validation
- Two-factor authentication (OTP)
- Email/SMS verification support
- Role & privilege loading
- User reactivation
- SQL repository included
- Pluggable password hashing
- Pluggable mail provider
- Pluggable OTP storage
- Fully extensible through interfaces

---

## Installation

```bash
npm install authen-service
```

or

```bash
yarn add signup-service
```

---

## Philosophy

Unlike traditional authentication libraries, **authen-service** contains only authentication business logic.

It does **not** depend on:

- Express
- NestJS
- Fastify
- Passport
- JWT libraries
- Prisma
- TypeORM
- Mongoose
- bcrypt
- argon2
- Nodemailer

Instead, every infrastructure component is injected through interfaces.

```text
Application
      │
      ▼
Authenticator
      │
 ┌────┼─────────────┐
 ▼    ▼             ▼
User Repository   Password Compare
Code Repository   Password Hash
Mail Sender       Privilege Loader
```

This makes the library reusable across virtually any architecture.

---

## Authentication Workflow

The built-in authentication flow performs:

```text
Validate request
        │
        ▼
Load user
        │
        ▼
Verify password
        │
        ▼
Check locked account
        │
        ▼
Check disabled account
        │
        ▼
Check suspended account
        │
        ▼
Check password expiration
        │
        ▼
Check access date
        │
        ▼
Check access time
        │
        ▼
Two-factor authentication
        │
        ▼
Load privileges
        │
        ▼
Authentication success
```

---

## Basic Usage

```typescript
import {
  useAuthenticator,
  initializeStatus
} from "authen-service"

const authenticator = useAuthenticator(
  initializeStatus(),
  undefined,
  undefined,
  userRepository,
  privilegeRepository,
  30,
  5,
  sendOTP,
  300,
  codeRepository,
  comparePassword,
  hash,
)

const result = await authenticator.authenticate({
  username: "john",
  password: "secret"
})
```

---

## User Repository

The library only requires a simple repository.

```typescript
interface UserRepository<ID> {
  getUser(username: string): Promise<UserInfo<ID> | undefined>

  pass?(
    userId: ID,
    deactivated?: boolean
  ): Promise<boolean>

  fail?(
    userId: ID,
    failCount?: number,
    lockedUntilTime?: Date | null
  ): Promise<boolean>
}
```

Your implementation can use:

- PostgreSQL
- MySQL
- Oracle
- SQL Server
- MongoDB
- DynamoDB
- Redis
- REST API
- LDAP
- Active Directory

---

## Password Verification

The library never hashes passwords directly.

Instead, inject your preferred implementation.

```typescript
const compare = async (
  plaintext: string,
  hashed: string
) => bcrypt.compare(plaintext, hashed)
```

Supported algorithms include:

- bcrypt
- argon2
- scrypt
- PBKDF2
- Custom implementations

---

## Two-Factor Authentication

OTP is completely optional.

Supported workflow:

```text
Username + Password
        │
        ▼
Generate OTP
        │
        ▼
Store hashed OTP
        │
        ▼
Send Email / SMS
        │
        ▼
Verify OTP
        │
        ▼
Authentication Success
```

You can plug in your own:

- Email provider
- SMS gateway
- OTP storage
- OTP hashing

---

## Password Expiration

Supports configurable password expiration policies.

```text
Password Modified Time
        +
Maximum Password Age
        │
        ▼
Password Expired
```

---

## Account Locking

Supports automatic account locking after configurable failed login attempts.

```text
Login Failure
      │
      ▼
Failure Counter
      │
      ▼
Maximum Attempts
      │
      ▼
Lock Account
      │
      ▼
Automatic Unlock
```

---

## Access Control

Supports:

- Disabled accounts
- Suspended accounts
- Deactivated accounts
- Access date range
- Access time range

Example date restriction:

```text
2025-01-01
      │
      ▼
2025-12-31
```

Example time restriction:

```text
08:00
  │
  ▼
18:00
```

---

## Privileges

Privileges can be loaded automatically after successful authentication.

```typescript
const privileges = await getPrivileges(userId)
```

The library converts flat privilege records into hierarchical trees.

```text
Administration
├── Users
├── Roles
└── Permissions

Reports
├── Sales
└── Inventory
```

Duplicate permissions can also be merged using bitwise OR.

---

## SQL Repository

The package includes a reusable SQL repository.

Only four database operations are required:

```typescript
interface DB {
  query()
  execute()
  executeBatch()
  param()
}
```

Compatible with:

- PostgreSQL
- MySQL
- MariaDB
- SQL Server
- Oracle
- SQLite

---

## Framework Independence

Works with any backend framework:

- Express
- Fastify
- NestJS
- Koa
- Hono
- Bun
- AWS Lambda
- Azure Functions
- Google Cloud Functions

---

## Security Features

- Password hashing abstraction
- Password verification abstraction
- Failed login tracking
- Account lockout
- Automatic unlock
- Password expiration
- Two-factor authentication
- OTP expiration
- Access date restriction
- Access time restriction

---

## Why authen-service?

Most authentication libraries are tightly coupled to:

- Frameworks
- Databases
- ORMs
- Hashing algorithms
- Mail providers

**authen-service** focuses only on authentication business rules.

Everything else is replaceable.

This makes it suitable for:

- Enterprise systems
- Banking applications
- Government platforms
- Healthcare systems
- Microservices
- Legacy system integration
- Cloud-native architectures

---

## API Overview

### Core

- `Authenticator`
- `useAuthenticator()`
- `initializeStatus()`

### Repository

- `UserRepository`
- `CodeRepository`
- `SqlUserRepository`

### Authentication

- Password verification
- Account locking
- Password expiration
- Two-factor authentication

### Authorization

- Privilege loader
- Privilege tree builder
- Permission merging

### Utilities

- Date helpers
- Mapping helpers
- SQL update builder
- OTP generator

---

## License

MIT

---

## Contributing

Contributions, issues, and feature requests are welcome.

If you find a bug or have an idea for improvement, please open an issue or submit a pull request.