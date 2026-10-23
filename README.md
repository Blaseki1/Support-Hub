# Support Hub

Internal hub: per-person logins and permissions, an audit log, and lookups that read from Superset
(Search Hub, Transaction History with Excel download; the other modules are placeholders until their curls are added).

## Set it up, step by step

**1. MongoDB (free Atlas cluster)**
1. Sign in at https://cloud.mongodb.com and create a project, then **Create a cluster** (the free M0 tier is fine).
2. **Database Access** > Add Database User. Choose a username and password, role "Read and write to any database". Keep them.
3. **Network Access** > Add IP Address. Add the address of the machine that runs this app (use your server's public IP; avoid 0.0.0.0/0 outside testing).
4. **Connect** > Drivers > copy the connection string. Replace `<password>` with the database user's password. Special characters in the password must be URL-encoded.

**2. Install**
1. Install Node.js 20 or newer. Unzip the project and open a terminal in it.
2. `npm install`
3. Copy `.env.example` to `.env`.

**3. Fill in `.env`**
1. `MONGODB_URI`: the string from step 1.
2. `APP_ENCRYPTION_KEY`: run `openssl rand -hex 32` and paste the result. Back it up somewhere safe. If it is lost, encrypted data cannot be read.
3. `ADMIN_EMAIL`, `ADMIN_NAME`: your details. `ADMIN_PASSWORD`: leave blank and a random one is printed at first start.
4. If you serve it over https, set `COOKIE_SECURE=true` (and `TRUST_PROXY=true` behind a proxy).

**3b. Seed the database (optional but recommended)**
`npm run seed` creates the collections and indexes, your admin account and the default Superset connections. Safe to run again. Add `-- --demo` to also create three example people (their temporary passwords are printed). Starting the app does the admin part on its own, so this step mainly sets up indexes and examples.

**4. Start**
1. `npm start` (the app reads `.env` by itself. Nothing to export, and it works on Windows too). On start it prints which store it is using: it must say `store: mongo`.
2. Open http://localhost:3000, sign in with the admin email and the printed password, and choose a new password when asked.

**5. Connect Superset (no Superset username or password needed)**
1. In Superset, open the dashboard in your browser, open the browser's developer tools (Network), find the `chart/data` request, right-click it and choose **Copy as cURL**.
2. In the hub open **Data Sources**, edit a connection, paste the curl into "Or paste a curl" and click **Fill**. (The curl's `-b 'session=…'` cookie and `X-CSRFToken` are what Superset needs.) This fills the address and IDs and saves the login (cookie / token) from the curl, encrypted, for the environment on that tab (UAT or PROD).
3. Save the connection. Repeat for each connection. The UAT login is also used for all three UAT connections.
4. Click **Test** on a connection card to check the address, IDs and login. A green message means it works; a red one says what is wrong. The server also keeps the renewed session cookie Superset sends back, so a login lasts longer when it is in use.
5. A browser login expires. When a search says "Superset rejected the saved login", paste a fresh curl the same way.

**6. Add your people**
Users & Permissions > Add person. Give them the temporary password shown once. They must change it at first sign-in. Switch export, download and each module on or off per person.

**7. Going to PROD**
Data Sources > open the PROD tab, paste the PROD curl and Fill, Save, then choose PROD as the live environment.

Try it with no MongoDB or Superset: `node test/fake-superset.js &` then `STORE=memory npm start`, and in Data Sources set the address to http://127.0.0.1:8091. In the fake, paste any curl that has `-H 'Cookie: session=abc' -H 'X-CSRFToken: csrf1' -H 'Authorization: Bearer tok1'`.
Tests: `npm test`.

## How it is protected
- **Passwords** are never stored. Only a bcrypt hash of the password (with a secret pepper from your key) is stored, which cannot be decrypted, only checked. This is stronger than encrypting them.
- **Names, emails, session names, audit text and the saved Superset login** are encrypted (AES-256-GCM) before they reach MongoDB. Emails are looked up by a keyed hash.
- Not encrypted: user ids, roles, permissions, timestamps, IP addresses and which module was used.
- Sessions use a random token; only its hash is stored. Cookie is HttpOnly and SameSite=Strict. Five wrong passwords lock that email+IP for 15 minutes.
- Permissions are checked on the server on every request. Excel download is enforced server-side; CSV export of on-screen results is only enforced in the page.
- Search values may contain letters, numbers, spaces and `@ . _ + -` only.
- "Match all" in Search Hub filters the Superset result on the server (the dataset itself matches any filled field). A row-limit warning shows if Superset hits its limit.

## Not covered yet
Fees, Limits, Giftcards and GPL modules (waiting on their curls), MFA, deleted-account images.
