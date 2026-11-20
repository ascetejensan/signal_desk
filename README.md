# CTI Sentinel | AI Threat Intelligence Chatbot

I am **Ishan Mahansaria** (USN **24BTRCL085**, AIML B). I maintain this project as my authorized adaptation of [Signal Desk](https://github.com/SOLANKYYY/signal-desk) for NoSQL Database using MongoDB (23CSE528, faculty Sujeet Jagtap).

**Goal:** I deploy CTI Sentinel as a hosted HTTPS website so my professor can open it on any computer without installing Git, Docker, MongoDB, Ollama or Python.

The application uses a Flask backend, MongoDB Atlas, a VirusTotal hash-reputation lookup, and optional hosted Gemini/OpenAI AI inference. Provider access is configured with server-side environment variables, not committed credentials.

## Deployment

I follow [HOSTING_SETUP.md](HOSTING_SETUP.md) to connect this GitHub repository to Vercel. The original Signal Desk source is imported automatically from its verified upstream revision by a GitHub Actions workflow. I preserve source attribution in [SOURCE_ATTRIBUTION.md](SOURCE_ATTRIBUTION.md).

## Security

I never put MongoDB connection strings, API keys, or login passwords into source code or public files. I replace any previously disclosed credentials before publishing.

**Status:** All application source files are present, and GitHub's source assembly and automated tests passed. My production Vercel deployment remains pending account-side project creation, securely configured environment variables, and live verification.

## Read-only access without an account

I offer a public `/demo` page alongside the full authenticated workspace. My professor can open `https://MY-VERIFIED-VERCEL-DOMAIN/demo` from any browser after I deploy the site. I will replace this placeholder with my actual tested URL. The preview includes a genuine bundled public-source snapshot and a browser-local file hash demonstration. It cannot change database records, submit API requests to VirusTotal, or open private chat history.

**I never put application passwords or server API keys in the public demo.**

## Run anywhere

I use [HOSTING_SETUP.md](HOSTING_SETUP.md) for my web hosting instructions. I go to https://vercel.com/new/import, choose `ascetejensan/signal_desk`, configure the listed production variables securely, and deploy. Vercel will provide a public HTTPS link once deployment succeeds.

I do not expect my professor to install Git, Python, Ollama, MongoDB or Docker. My professor can visit that HTTPS address from a browser. I retain an application login for access to protected features and share the website login privately, not the server API keys.

I have **not yet verified a live production URL**. I treat the deployment as pending until I test the public HTTPS URL from another device.

[GitHub automated test results](https://github.com/ascetejensan/signal_desk/actions/workflows/verify-cti.yml)

