import {
  assertFails,
  initializeTestEnvironment,
  RulesTestEnvironment,
} from '@firebase/rules-unit-testing';
import * as fs from 'fs';

let testEnv: RulesTestEnvironment;

export async function runSecurityRulesTests() {
  testEnv = await initializeTestEnvironment({
    projectId: 'focal-ego-fvxch',
    firestore: {
      rules: fs.readFileSync('firestore.rules', 'utf8'),
    },
  });

  const unauthedDb = testEnv.unauthenticatedContext().firestore();
  const nonAdminVerifiedDb = testEnv
    .authenticatedContext('user_1', {
      email: 'customer@example.com',
      email_verified: true,
    })
    .firestore();
  const unverifiedAdminDb = testEnv
    .authenticatedContext('admin_spoof', {
      email: 'raphealogar24@gmail.com',
      email_verified: false,
    })
    .firestore();
  const verifiedAdminDb = testEnv
    .authenticatedContext('admin_1', {
      email: 'raphealogar24@gmail.com',
      email_verified: true,
    })
    .firestore();

  const validNow = new Date();
  const baseValidPayload = {
    name: 'Tiger Nut Milk',
    category: 'Non-Carbonated',
    description: 'Freshly blended tiger nut drink served chilled.',
    price: 800,
    emoji: '🥛',
    imageUrl: 'https://example.com/tigernut.jpg',
    isPublished: true,
    ownerId: 'admin_1',
    createdAt: validNow,
    updatedAt: validNow,
  };

  // 1. Unauthenticated Write
  await assertFails(unauthedDb.collection('products').doc('prod_1').set(baseValidPayload));

  // 2. Non-Admin Verified User Write (Uploading picture/good as non-admin must fail)
  await assertFails(
    nonAdminVerifiedDb.collection('products').doc('prod_1').set({
      ...baseValidPayload,
      ownerId: 'user_1',
    })
  );

  // 3. Unverified Admin Email Spoof
  await assertFails(
    unverifiedAdminDb.collection('products').doc('prod_1').set({
      ...baseValidPayload,
      ownerId: 'admin_spoof',
    })
  );

  // 4. Identity Spoofing on Create by Admin
  await assertFails(
    verifiedAdminDb.collection('products').doc('prod_1').set({
      ...baseValidPayload,
      ownerId: 'someone_else',
    })
  );

  // 5. Shadow Field Injection
  await assertFails(
    verifiedAdminDb.collection('products').doc('prod_1').set({
      ...baseValidPayload,
      shadowField: true,
    })
  );

  // 6. Oversized Description (> 1000 chars)
  await assertFails(
    verifiedAdminDb.collection('products').doc('prod_1').set({
      ...baseValidPayload,
      description: 'A'.repeat(1005),
    })
  );

  // 7. Negative Price
  await assertFails(
    verifiedAdminDb.collection('products').doc('prod_1').set({
      ...baseValidPayload,
      price: -100,
    })
  );

  // 8. ID Poisoning
  await assertFails(
    verifiedAdminDb
      .collection('products')
      .doc('invalid id with spaces!')
      .set(baseValidPayload)
  );

  // 9. Forged Creation Timestamp
  await assertFails(
    verifiedAdminDb.collection('products').doc('prod_1').set({
      ...baseValidPayload,
      createdAt: new Date(2020, 1, 1),
    })
  );

  // 10. Owner Hijack on Update
  await assertFails(
    verifiedAdminDb.collection('products').doc('prod_1').update({
      ownerId: 'hijacked_owner',
    })
  );

  // 11. Unauthorized Privilege Escalation (/admins write)
  await assertFails(
    nonAdminVerifiedDb.collection('admins').doc('user_1').set({
      uid: 'user_1',
      createdAt: validNow,
    })
  );

  await testEnv.cleanup();
}
