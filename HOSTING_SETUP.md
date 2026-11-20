# Hosting CTI Sentinel so my professor can open it anywhere

I am **Ishan Mahansaria** (USN **24BTRCL085**). I use this repository to deploy the same Flask website architecture as the Signal Desk reference project, customized for CTI Sentinel.

## What I need

I need a **Vercel account connected to my GitHub** and my existing **MongoDB Atlas M0 cluster**. I do not need to keep my laptop on, run Docker on my professor's computer, or install Ollama on his machine. Vercel runs Flask and holds the server-only environment variables.

I have already shared older credentials in a conversation. I must rotate those credentials before setting up a publicly reachable server. I must never add live secrets to a repository, .env example, README, screenshot, or downloadable ZIP.

## Step 1 — Import my GitHub repository

1. I sign in at https://vercel.com/new using GitHub.
2. I select the GitHub repository `ascetejensan/signal_desk`.
3. I choose the repository root `./` as the Root Directory. I verify that `app.py`, `vercel.json` and `requirements.txt` exist at that root after the assembly workflow.
4. I select or allow Vercel to detect the Python Flask framework.
5. I leave the output directory unset and retain the repository's `vercel.json`.
6. I configure server-only environment variables before deploying.

## Step 2 — My server-side environment variables

| Setting | What I enter in Vercel's Project → Settings → Environment Variables |
|---|---|
| `MONGODB_URI` | My **new, rotated** MongoDB Atlas driver URI |
| `MONGODB_DB` | `cti_sentinel_web` (or a separate dedicated database of my choice) |
| `APP_USERNAME` | `ishan` |
| `APP_PASSWORD` | My **new** unique website password of 16+ characters |
| `VIRUSTOTAL_API_KEY` | My **new, rotated** VirusTotal API key |
| `CRON_SECRET` | A separate randomly generated secret of 32+ characters |
| `LLM_BACKEND` | `gemini` if I have a Gemini Developer API key |
| `GEMINI_API_KEY` | My Gemini key, if I activate hosted AI |
| `GEMINI_MODEL` | A model available in my Gemini API project (check provider list) |
| `EMBEDDING_MODEL` | `gemini-embedding-001` for the repository's Gemini example |
| `EMBEDDING_DIMENSIONS` | `3072` for the configured example |
| `CHAT_RETRIEVAL` | `exact` |

I configure these for **Production** and redeploy whenever I update them. I do not place API keys in browser JavaScript.

The application supports optional OpenAI with `LLM_BACKEND=openai`, `OPENAI_API_KEY`, `OPENAI_MODEL`, `EMBEDDING_MODEL=text-embedding-3-small`, and `EMBEDDING_DIMENSIONS=1536`. I choose only a provider I can access and verify.

**I cannot use `OLLAMA_BASE_URL=http://host.docker.internal:11434` from Vercel.** That address refers to my local Docker host. I use hosted Gemini or OpenAI for a remotely accessible chatbot, or I separately host an Ollama instance on an internet-accessible secured server.

**VirusTotal:** My website's current integration checks known *file hashes*, not an arbitrary website URL. Its API expects `VIRUSTOTAL_API_KEY`, not `VT_API_KEY`.

## Step 3 — Make Atlas reachable from Vercel

I create or rotate a dedicated Atlas database user with only the required permissions for `cti_sentinel_web`. I do not reuse a broad administrative account for public hosting.

Because Vercel outbound IP addresses are dynamic, I configure Atlas networking using the official MongoDB Atlas–Vercel integration where appropriate, or deliberately add a temporary `0.0.0.0/0` Atlas access-list entry with strong scoped credentials and TLS. That entry allows connection *attempts* from any IPv4 address, so I review the exposure and remove the broad access when I have a safer networking arrangement. I never add my old leaked database password.

## Public access without passwords

I include a separate `/demo` route that my professor can open in any browser without creating an account or entering a password. Once Vercel issues my HTTPS domain, the public demo address will be `https://MY-VERIFIED-DEPLOYMENT.vercel.app/demo`. I will replace this placeholder only after verifying my actual deployment URL.

The demo is deliberately **read-only**: it uses the bundled public intelligence snapshot and computes file SHA-256 locally in the browser. It does not expose MongoDB records beyond the public snapshot, private investigation notes, chat history, VirusTotal requests or credentials. The complete research workspace still requires the configured username and private website password. I do not claim that the demo is a live threat feed.

## Step 4 — Verify the live deployment

Once deployment completes, Vercel gives me a production HTTPS URL. **This URL does not exist until deployment succeeds.** I test it from my phone on mobile data and from an incognito browser, not only from my laptop.

I sign in with username `ishan` and the new website password. I can select **Remember me for 7 days** for convenience. My professor does **not** need an Atlas, VirusTotal, Docker, Git, or Ollama account. I give him the production link and an application login through a private channel.

I verify `/api/health` after signing in, the Threat Explorer event list, the File & Message Checks tab, and VirusTotal hash lookup. If the hosted AI provider is configured, I add evidence, ask a question, inspect its cited sources, and reload to verify chat history.

I check Vercel deployment logs and Atlas metrics if an action fails. I do not claim that a successful build alone proves live connectivity or successful model inference.

## Security and limitations

I retain website authentication. I do not expose database writes or paid API operations to anonymous visitors because public unauthenticated API usage could consume quotas or alter my coursework data.

I have not configured Vercel for this account merely by committing GitHub files. I need to connect my Vercel account, set secret environment variables, and verify the resulting URL.
