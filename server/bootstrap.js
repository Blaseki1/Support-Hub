const A = require('./auth');
const D = require('./defaults');
// Creates the first admin when there are no users yet.
async function ensureAdmin(store, config) {
  const existing = await store.listUsers();
  if (existing.length) { // new modules appear for Admins automatically
    for (const u of existing) if (u.role === 'Admin') { const want = [...new Set([...(u.perms || []), ...D.roleDefaults('Admin')])]; if (want.length !== (u.perms || []).length) await store.updateUser(u.id, { perms: want }); }
    return null;
  }
  const pw = config.adminPassword || A.tempPassword();
  await store.createUser({ name: config.adminName, email: config.adminEmail, role: 'Admin', perms: D.roleDefaults('Admin'), status: 'active', passwordHash: await A.hash(pw), mustChange: true });
  console.log('\n  First admin created.\n  Email:    ' + config.adminEmail + '\n  Password: ' + pw + '\n  You will be asked to change it at first sign-in.\n');
  return pw;
}
module.exports = { ensureAdmin };
