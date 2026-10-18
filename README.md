# Friends Hub

Hub privato per un gruppo di amici, costruito attorno a un **Master Account Google** (Calendar + Drive).

## Architettura
```
Browser ──HTTPS──> Node/Express ──> Google Calendar API (master)
  │  └─WebSocket─>  + Socket.IO  ──> Google Drive API   (master)
  │                 + SQLite (utenti, ruoli, chat, ACL)
  └─ login Google OAuth (solo identità: openid/email/profile)
```
- Gli utenti **non** danno accesso ai loro dati Google: il login serve solo a identificarli.
- Il backend usa un refresh token del master account (solo server-side) per Calendar e Drive.
- Il browser non parla mai direttamente con Google: ogni richiesta passa dai controlli RBAC.

## Ruoli e permessi (`src/rbac.js`)
| Permesso | Admin | Membro Avanzato | Spettatore |
|---|---|---|---|
| Calendario: leggi / scrivi | ✔ / ✔ | ✔ / ✔ | ✔ / ✘ |
| Note: leggi / scrivi | ✔ / ✔ | ✔ / ✔ | ✔ / ✘ |
| Chat: leggi / scrivi | ✔ / ✔ | ✔ / ✔ | ✔ / ✘ |
| Utenti, ruoli, chat, accessi, pulizia calendario | ✔ | ✘ | ✘ |

Due livelli di controllo: **permesso globale** (dal ruolo) + **accesso alla risorsa** (tabella `access`: per utente o per ruolo, solo per chat e cartelle). L'admin vede tutto.
Nuovi utenti: `pending` finché l'admin non li approva.

## Setup
1. Google Cloud Console: crea progetto, abilita Calendar API e Drive API, crea credenziali OAuth (Web) con redirect `BASE_URL/auth/callback` e `http://localhost:4000`.
2. `cp .env.example .env` e compila `GOOGLE_CLIENT_ID/SECRET`, `ADMIN_EMAIL` (= master account), `SESSION_SECRET`.
3. `npm i && npm run master-token` → accedi col master account, copia `MASTER_REFRESH_TOKEN` in `.env`.
4. Su Drive del master crea una cartella radice per le note, copia l'ID in `NOTES_ROOT_FOLDER_ID`; le sottocartelle sono le "cartelle di testo".
5. `npm start`. Il primo login con `ADMIN_EMAIL` diventa admin; invia il link agli amici via WhatsApp e approvali da `/api/admin/users`.

## Da completare
- Frontend: pannello admin pronto in `public/admin.html`; calendario mensile in `public/calendar.html`; mancano le viste Note e Chat.
- Sync calendari personali (opzionale): scope incrementale `calendar.freebusy` per utente, token cifrati a riposo, controllo conflitti prima di creare un evento.
- Store di sessione persistente, rate limiting, CSRF token per le richieste mutanti, backup di `hub.db`.
