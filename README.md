# Family Trip Portal on Netlify

The page is served from `public/`. A small Netlify Function (`netlify/functions/api.mjs`) acts as the server: it talks to Supabase on the browser's behalf. The Supabase address and key are stored as Netlify environment variables, so they **never appear in the page or the browser**.

```
family-trip-portal/
├── public/index.html             ← the portal page (no secrets)
├── netlify/functions/api.mjs     ← the server part (sign-in, trips, family, receipts)
├── netlify.toml                  ← Netlify settings + security headers
├── package.json                  ← lists the Supabase library the function uses
├── setup.sql                     ← one-time Supabase database setup
├── .env.example                  ← template, only for testing on your own computer
└── .gitignore                    ← keeps .env and Netlify's local files out of git
```

---

## Part 1: Supabase (one time, about 10 minutes)
1. Create a project at **supabase.com** and choose the **Singapore** region.
2. **SQL Editor → New query.** Open `setup.sql`, change `you@example.com` and `Your name` on the last line to **your own email address and name**, paste the whole file in, and click **Run**.
3. **Authentication → Email Templates → Magic Link.** Add this line to the message, then save:
   `Your sign-in code is {{ .Token }}`
4. **Project Settings → API.** Keep this tab open. You'll need the **Project URL** and the **anon public** key in Part 2.

## Part 2: Netlify (about 10 minutes, in Terminal)
Open **Terminal** on your Mac and run these lines one at a time.

```bash
# 1. Go to the portal folder
cd ~/"AI Projects"/family-trip-portal

# 2. Check Node.js is installed (needs v18 or newer). If "command not found", install the LTS from nodejs.org first.
node --version

# 3. Install the Netlify command-line tool (add "sudo " in front if you get a permission error)
npm install -g netlify-cli@latest

# 4. Log in. A browser window opens; sign up or log in, then click "Authorize".
netlify login

# 5. Create your site and link this folder to it. Pick your team if asked.
#    The name becomes your address, e.g. https://poon-family-trips.netlify.app (it must be unique).
netlify sites:create --name poon-family-trips

# 6. Store the secrets in Netlify (paste your own values from Supabase between the quotes)
netlify env:set SUPABASE_URL "https://YOUR-PROJECT.supabase.co"
netlify env:set SUPABASE_ANON_KEY "PASTE-ANON-KEY"
netlify env:set SECRET_KEY "$(openssl rand -hex 32)"

# 7. Install the Supabase library the function uses, then publish
npm install
netlify deploy --prod
```

The last command prints your **Website URL**.

## Part 3: Finish up
1. In Supabase, go to **Authentication → URL Configuration**. Set **Site URL** to your Netlify address and also add it under **Redirect URLs**.
2. Open your Netlify address. Choose **Email me a code**, enter your email, and type in the 6-digit code from the email.
3. Go to the **Family** tab and add each family member's email address. Send them the link.

## Updating later
- **Changed a file?** Run `cd ~/"AI Projects"/family-trip-portal && npm install && netlify deploy --prod` again. If GitHub is linked, just `git push`; Netlify runs `npm install` for you.
- **Changed a secret?** Run `netlify env:set NAME "new value"`, then `netlify deploy --prod`. Netlify picks up new values on the next deploy.
- **Custom domain:** Netlify dashboard → your site → **Domain management**. HTTPS is set up automatically.

## Security in this version
- **Nothing to steal from the page.** The browser never sees the Supabase address, key or storage links. It only calls `/api/...` on your own site.
- **Login cookie:** encrypted (AES-256-GCM), `HttpOnly` (page scripts can't read it), `Secure` (sent over HTTPS only) and `SameSite=Lax`.
- **Database rules:** Supabase row-level security (from `setup.sql`) still applies to every request. Only emails on the family list see anything, and only admins can delete trips or change the family list.
- **Cross-site requests:** every change needs a custom `X-Portal` header, which other websites can't add.
- **Browser protections:** strict Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff` and HSTS (set in `netlify.toml`).
- **Receipts:** stored in a private bucket and streamed only to signed-in family members.
  - Photos are shrunk in the browser before uploading.
  - PDFs can be up to 4 MB, because Netlify functions accept at most 6 MB per request.

## Good to know
- Netlify's free plan is plenty for one family.
- **Supabase pauses:** the free plan pauses a project after about a week with no use. If sign-in stops working, log in to supabase.com and click **Restore project**.
- **Backups:** use **All trips → Back up all trips (JSON)** every so often.
- **Sign-in attempts:** they're rate-limited per server instance, and Supabase applies its own limits on top.
