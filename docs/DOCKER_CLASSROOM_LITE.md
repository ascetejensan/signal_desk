# CTI Sentinel Classroom Lite — one image, built in GitHub's cloud

This is the low-memory packaging option for my MongoDB / AI Threat Intelligence mini project. **I do not build the several-gigabyte Docker image on my 8 GB Windows laptop.** GitHub Actions builds and uploads it remotely.

## What is inside the image

- The current CTI Sentinel Flask website and source code, including the VirusTotal file/URL scanner UI.
- A **local MongoDB 8 Community** server and the bundled public threat-intelligence snapshot; no private Atlas data or credentials.
- **Ollama `llama3.2:1b`** — a smaller chat model that is more practical than `llama3.2:3b` on low-memory hardware.
- **Ollama `nomic-embed-text`**, baked into the same image for local embeddings.
- A local-only web login: username `ishan` and a generated password printed in the startup logs.

The image can operate the local database and Ollama chatbot without calling Gemini or MongoDB Atlas. The actual quality of chatbot responses may be lower than the 3B version. **This is a single application/database instance, not a substitute for separate replica-set, sharding and multi-database lab environments.**

**No credentials are embedded.** Do not place `MONGODB_URI`, the Atlas password, `VIRUSTOTAL_API_KEY`, a hosted API key, or your hosted web-login password in the Dockerfile or the published image. A public image is fully inspectable by anyone who pulls it.

## Build the image remotely, without Docker Desktop

1. Open [Build CTI Sentinel classroom image in GitHub cloud](https://github.com/ascetejensan/signal_desk/actions/workflows/classroom-image.yml).
2. The workflow automatically runs for changes to the classroom Docker build files. If necessary, click **Run workflow** and choose **lite**.
3. The GitHub-hosted runner builds the complete image, downloads both models **during the build**, pushes it to **GitHub Container Registry**, then attempts to smoke-test the website, local database and model inventory.
4. Only after the workflow reports **success**, use the image tag below. A green code test alone does not prove the image build passed.

| Option | Built-in chat model | Image tag |
|---|---|---|
| **Lite (recommended for 8 GB laptops)** | `llama3.2:1b` | `ghcr.io/ascetejensan/cti-sentinel-classroom:lite` |
| Full (more memory required) | `llama3.2:3b` | `ghcr.io/ascetejensan/cti-sentinel-classroom:full` |

The `full` tag is **not created until the full workflow is run successfully**.

### Allow my professor to pull without a GitHub login

GitHub Container Registry typically creates a new container package as **private**, even when the source repository is public. After the package is published:

1. Open the [package list](https://github.com/ascetejensan?tab=packages) on my GitHub profile.
2. Select `cti-sentinel-classroom` → **Package settings** → **Change visibility**.
3. Set it to **Public** after confirming the image contains no private credentials or data.

A public GitHub Container Registry image can be pulled anonymously. If the package is still private, a teacher without GitHub access will see a permissions error.

## My professor's Windows laptop — one pull, one run

**Prerequisites:** Windows with Docker Desktop and its **Linux Engine working**, sufficient free disk space and memory. The image contains the models, but the laptop still needs resources to execute them. The cloud build avoids large local compilation; it does **not** repair a broken Docker Engine or remove runtime RAM usage.

In **PowerShell**:

```powershell
docker version
docker pull ghcr.io/ascetejensan/cti-sentinel-classroom:lite

docker run -d --name cti-classroom --restart unless-stopped `
  -p 127.0.0.1:8765:8765 `
  --mount type=volume,source=cti-classroom-db,target=/data/db `
  --mount type=volume,source=cti-classroom-config,target=/data/configdb `
  ghcr.io/ascetejensan/cti-sentinel-classroom:lite

docker logs --tail 80 cti-classroom
```

Open **http://localhost:8765/**, sign in as `ishan` using the generated password shown in `docker logs`. No local `git clone`, `docker build`, `ollama pull`, or MongoDB/Python installation is needed after pulling.

A saved local MongoDB volume keeps the public snapshots and subsequent local work. Never delete volumes while preserving lab evidence matters.

To stop and start again:

```powershell
docker stop cti-classroom
docker start cti-classroom
```

If the container already exists, use `docker start cti-classroom`, not another `docker run` with the same name.

## Optional online VirusTotal checks

The offline demo supports local SHA-256 hashing without an API key. File-hash lookup, URL reputation and uploads require an online connection and a **privately supplied** `VIRUSTOTAL_API_KEY` at **runtime**. Only upload files that are safe to share with VirusTotal's security partners. The image does not include your hosted VirusTotal key.

Do not pass the key on a public command line in a classroom. If required, configure private Docker Compose secrets or an environment file stored **only on the professor's machine** and kept outside GitHub and the image. The user must be authorized to use the API key.

## Resource trade-offs and honest status

- The `lite` model is significantly smaller than `llama3.2:3b`, but it will not perform identically. This trades some answer quality for lower memory and download size.
- The full website and historical data remain included. Private Atlas documents, cloud conversations and previous Atlas users are **not** copied.
- Ollama model files live in the image, so initial `docker pull` still downloads a large image. No **separate** model download is needed.
- Some computationally heavy MongoDB lab topologies require distinct containers or servers and are not actually replicated by this single-process classroom database.
- The local image serves only the professor's loopback interface (`127.0.0.1`); do not expose its port publicly.
- GitHub Actions smoke tests exercise startup and model inventory. They are not a complete security audit or full end-to-end exercise validation.

## Source and attribution

- [Classroom Dockerfile](../Dockerfile.classroom)
- [Startup script](../docker/classroom-entrypoint.sh)
- [Remote build-and-test workflow](../.github/workflows/classroom-image.yml)
- [Main CTI Sentinel README](../README.md)
- [Original Signal Desk source attribution](../SOURCE_ATTRIBUTION.md)

**The existing Vercel-hosted CTI Sentinel website at https://cti-sentinel-ishan.vercel.app remains independent of this local Docker image.**
