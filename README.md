# ZhuoMarket Backend — Production V28 / Zhuo Support

## Render env vars
Required: `DATABASE_URL`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `OWNER_EMAIL`, `CORS_ORIGINS`.
Optional/feature-gated: `OPENAI_API_KEY`, `OPENAI_MODEL`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_ENV`, `VAPID_SUBJECT`, `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`.

MonCash/NatCash credentials are accepted as configuration only (`MONCASH_API_BASE_URL`, `MONCASH_API_KEY`, `MONCASH_API_SECRET`, `NATCASH_API_BASE_URL`, `NATCASH_API_KEY`, `NATCASH_API_SECRET`). Their transaction request schema is not guessed; enable only after the official merchant API contract is available.

## Payments
- Stripe uses server-created Checkout Sessions and a signed webhook at `/api/webhooks/stripe`.
- PayPal uses the Orders v2 create/capture flow on the server.
- Card/PayPal are enabled automatically only when their server credentials exist.
- Cash on delivery is available without a gateway.

## Notifications
Web Push uses VAPID keys and stores subscriptions per authenticated user. `insertNotification()` triggers a push for the user when a subscription exists.

## Data
No seeded demo products, demo orders, local streaming prices, or local streaming requests are used by the production frontend. Products, promotions, streaming plans, orders, cart and wishlist are backend-backed.


V28 deep QA: PayPal capture is bound to the stored order reference; cancelled/failed/refunded orders restore reserved stock once.


## Zhuo Support
- `/api/chatbot` is authenticated and serves Zhuo Support AI.
- Serious support cases are summarized and escalated automatically to admin notifications.
- `/api/support/config` exposes the support configuration needed by the frontend.
- Admin can store the support admin phone with `/api/admin/settings/support`.
- Customers do not receive a direct admin-chat endpoint through the support flow.
- The frontend may render AI replies in blue; this is a frontend presentation detail and requires no separate backend service.
