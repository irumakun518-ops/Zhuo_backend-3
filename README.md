# ZhuoMarket Backend V28

Backend Express/Node.js correspondant au frontend `ZhuoMarket_FINAL_V28_SUPPORT_BLUE_ADMIN_FIXED.html`.

## Render
Build: `npm install`
Start: `npm start`
Node: 20+

Variables obligatoires: `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`,
`CORS_ORIGINS`, `PUBLIC_BASE_URL`.

Le compte admin est créé automatiquement au démarrage.

Le frontend V28 utilise actuellement `https://zhuo-market-backend-3-n4k9.onrender.com`;
après déploiement, remplace `CONFIG.API_BASE` par l'URL réelle du service si elle diffère.

## Routes couvertes
- Health, auth/register/login/me/logout/refresh
- Products CRUD, promotions CRUD, brands
- Upload images
- Orders + statut admin
- Notifications + préférences + user-state
- Support client/admin et chatbot
- Trades
- Payment methods
- Stripe checkout/session
- PayPal create/capture
- Manual payment confirmation
- Streaming plans + admin CRUD
- Admin stats/users/messages/team/notifications
- Trade/support admin settings
- Confirmation code
- Push public key/subscription

## Stockage
Sans PostgreSQL: fichier JSON dans `data/db.json`.
Les fichiers uploadés sont dans `uploads/`. Sur Render sans disque persistant,
le stockage local peut être perdu après redéploiement/restart; pour production,
utilise un stockage objet/Cloudinary et une vraie base de données.

Les clés Stripe/PayPal/OpenAI restent uniquement côté backend.
