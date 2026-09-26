# Firestore Security Specification — R&P Nutriflow

## 1. Data Invariants

1. **Default Deny Catch-All**: Any path not explicitly matched under `/databases/{database}/documents` is denied for both `read` and `write`.
2. **Path Variable Hardening**:
   - Every wildcard ID (`productId`, `adminId`) must be a string with length between `1` and `128` characters matching `^[a-zA-Z0-9_-]+$`.
3. **Strict Schema Enforcement (`products/{productId}`)**:
   - Allowed & Required Keys (`hasAll` & `hasOnly`):
     - `name`: `string`, length `1..100`
     - `category`: `string`, length `1..60`
     - `description`: `string`, length `0..1000`
     - `price`: `int` or `float`, `0 <= price <= 10000000`
     - `emoji`: `string`, length `1..16`
     - `imageUrl`: `string`, length `0..300000` (supports HTTPS URLs or compressed data URLs under 300KB)
     - `isPublished`: `bool`
     - `ownerId`: `string`, length `1..128`, matching `^[a-zA-Z0-9_-]+$`
     - `createdAt`: `timestamp`
     - `updatedAt`: `timestamp`
4. **Timestamp & Ownership Integrity**:
   - On `create`: `ownerId == request.auth.uid`, `createdAt == request.time`, and `updatedAt == request.time`.
   - On `update`: `ownerId == request.auth.uid` and `updatedAt == request.time`.

## 2. Access Control Matrix

| Collection Path | `get` | `list` | `create` | `update` | `delete` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/products/{productId}` | Public if `resource.data.isPublished == true`, or `isAdmin()` | Public if `resource.data.isPublished == true`, or verified store admin (`raphealogar24@gmail.com`) | **Admin Only** (`isAdmin()`) with strict schema & `ownerId == request.auth.uid` | **Admin Only** (`isAdmin()`) with strict schema & `ownerId == request.auth.uid` | **Admin Only** (`isAdmin()`) |
| `/admins/{adminId}` | Verified user reading own record or `isAdmin()` | `false` | `false` (Managed out-of-band only) | `false` | `false` |

### Admin Identity Definition (`isAdmin()`)
- Must be signed in (`request.auth != null`) AND email-verified (`request.auth.token.email_verified == true`).
- Must either match the store owner's verified email (`request.auth.token.email == 'raphealogar24@gmail.com'`) OR have an existing document at `/databases/$(database)/documents/admins/$(request.auth.uid)`.

## 3. Adversarial Attack Scenarios

1. **Unauthenticated Write**: Anonymous visitor attempts to create or update a product in `/products/{productId}` -> Denied.
2. **Non-Admin Authenticated Write**: A logged-in, email-verified user (`customer@example.com`) attempts to upload a photo or create/update/delete a product -> Denied (`isAdmin()` is false).
3. **Unverified Email Admin Spoof**: A user with `email == 'raphealogar24@gmail.com'` but `email_verified == false` attempts to write to `/products/{productId}` -> Denied.
4. **Identity Spoofing on Create**: Admin attempts to create a product with `ownerId` set to another UID -> Denied.
5. **Shadow Field Injection**: Admin attempts to write an undeclared field `isAdmin: true` or `discount: 99` on a product -> Denied by `hasOnly`.
6. **Payload Size / DoS**: Admin submits a 5,000-character `description` or 500KB `imageUrl` -> Denied by `.size()` bounds.
7. **Negative Price**: Admin submits `price: -500` -> Denied by `price >= 0`.
8. **ID Poisoning**: Admin attempts to create a document with spaces or special characters in `productId` -> Denied by `isValidId(productId)`.
9. **Timestamp Forgery**: Admin attempts to set `createdAt` or `updatedAt` to a past/future timestamp -> Denied by `request.time` check.
10. **Owner Hijack on Update**: Admin attempts to change `ownerId` to a different UID during an update -> Denied.
11. **Privilege Escalation**: Any client attempts to create or modify `/admins/{adminId}` -> Denied (`allow write: if false`).
