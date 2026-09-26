# Firestore Security Specification — R&P Nutriflow

## 1. Data Invariants

1. **Default Deny Catch-All**: Any path not explicitly matched under `/databases/{database}/documents` is denied for both `read` and `write`.
2. **Path Variable Hardening**: Every single-document operation (`get`, `create`, `update`, `delete`) on `/products/{productId}` and `/admins/{adminId}` validates that the document ID is a string of length `1..128` matching `^[a-zA-Z0-9_\-]+$`.
3. **Admin-Only Catalog Management (`isAdmin`)**:
   - Only verified administrators (`request.auth.token.email_verified == true` and either `request.auth.token.email == 'raphealogar24@gmail.com'` or `exists(/databases/$(database)/documents/admins/$(request.auth.uid))`) can `create`, `update`, or `delete` documents in `/products/{productId}` (including uploading/updating product pictures and descriptions).
   - Non-admin users (even if authenticated and email-verified) are strictly prohibited from creating, updating, or deleting products.
4. **Strict Schema & Key Validation (`isValidProduct`)**:
   - Every product document must contain exact required keys: `['name', 'category', 'description', 'price', 'emoji', 'imageUrl', 'isPublished', 'ownerId', 'createdAt', 'updatedAt']` and no shadow keys (`hasAll` + `hasOnly`).
   - `name`: string, `1..100` chars.
   - `category`: string, `1..60` chars.
   - `description`: string, `0..1000` chars.
   - `price`: int or float, `0..10000000`.
   - `emoji`: string, `1..16` chars.
   - `imageUrl`: string, `0..300000` chars.
   - `isPublished`: boolean.
   - `ownerId`: string, `1..128` chars matching `^[a-zA-Z0-9_\-]+$`.
   - `createdAt` & `updatedAt`: `timestamp`.
5. **Identity & Temporal Integrity**:
   - On `create`, `incoming().ownerId == request.auth.uid`, `incoming().createdAt == request.time`, and `incoming().updatedAt == request.time`.
   - On `update`, `ownerId` and `createdAt` are immutable (`incoming().ownerId == existing().ownerId` and `incoming().createdAt == existing().createdAt`) and `incoming().updatedAt == request.time`.
6. **Query Enforcer (`allow list`)**:
   - `list` on `/products` evaluates `existing().isPublished == true || (isVerifiedUser() && request.auth.token.email == 'raphealogar24@gmail.com')`.

---

## 2. The "Dirty Dozen" Payloads

1. **Unauthenticated Write**: Creating a product with `auth == null`.
2. **Non-Admin Verified User Write**: Creating/uploading a product photo as a regular verified user (`user@example.com`).
3. **Unverified Admin Email Spoof**: Creating a product with `email: 'raphealogar24@gmail.com'` but `email_verified: false`.
4. **Identity Spoofing on Create**: Admin setting `ownerId: 'other_uid'` when `request.auth.uid == 'admin_uid'`.
5. **Shadow Field Injection on Create**: Admin adding `{ isVerified: true }` alongside valid Product fields.
6. **Oversized Description / Resource Exhaustion**: Admin setting `description` to a 2,000-character string (exceeds `maxLength: 1000`).
7. **Negative Price**: Admin setting `price: -500`.
8. **ID Poisoning**: Admin creating a document with a path ID containing spaces/special chars or exceeding 128 chars.
9. **Forged Creation Timestamp**: Admin creating a product with a past/future `createdAt` instead of `request.time`.
10. **Owner Hijack on Update**: Admin updating an existing product to change `ownerId` to another user.
11. **Immutable `createdAt` Mutation on Update**: Admin changing `createdAt` during an update.
12. **Unauthorized Privilege Escalation**: Writing to `/admins/{adminId}` from a client SDK.
