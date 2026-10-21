# Zex Store — deployment package

This package includes your existing storefront, an Express API, SQLite persistence, customer registration/login, order recording, and an admin-only order dashboard.

## Before launch
1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env` and set a long random `SESSION_SECRET`, a private `ADMIN_EMAIL`, and a unique `ADMIN_PASSWORD` (12+ characters). Never commit `.env`.
3. Set `NODE_ENV=production` when serving over HTTPS.
4. Run `npm install` then `npm start`.
5. Open `/`, create a customer account if wanted, then sign in with the configured admin email/password. The admin link appears for the admin account; `/admin` also checks the server-side role and blocks non-admins.

The first server start creates the admin account if it does not already exist. If an account with `ADMIN_EMAIL` exists, its role is promoted to admin; this does not reset its password.

## Deploy
Deploy to a Node.js host such as Render, Railway, or a VPS. Set the environment variables in the host dashboard, use `npm install` as build command and `npm start` as start command, and attach a persistent disk/volume for `data.sqlite` and `sessions.sqlite`. Set `DB_PATH` to a path on that persistent volume. Use HTTPS. Without persistent storage, SQLite data can be lost on redeploy/restart.

## Payment and order workflow
Customers choose a product and enter a UPI UTR. The order is stored as `pending_verification` for signed-in customers and guest checkout; the WhatsApp handoff remains available. In `/admin`, verify the payment in your bank/UPI app, then update status to paid/processing/completed or rejected/refunded. Never mark an order paid from the UTR alone.

## Important current limitations
- The store's product catalogue/prices are still hard-coded in `public/index.html`; the admin dashboard currently manages orders and status, not product prices.
- The storefront's Google sign-in and game-ID validation call external API routes that are not included in this package, so those optional features remain unavailable until configured with their respective providers.
- Payment is manual UPI confirmation, not an automatic payment gateway. No card details are collected or processed.
- The original storefront has a game login field for some game flows. Do not collect or forward game account passwords; the order flow has been adjusted not to include a password in the WhatsApp message, but remove any such fields from the catalogue if you do not legitimately need them.
- Before public launch, update all marketing copy, payment QR/UPI details, privacy/terms, and contact links to match your real business. Test an order end-to-end with a small amount.

## Admin security
Admin authorization is checked on the server for every `/api/admin/*` endpoint. Admin status is never accepted from a browser-supplied flag. Use a unique admin password, HTTPS, a persistent database, and keep environment secrets private.
