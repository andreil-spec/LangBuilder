# OAuth Token Forwarding Setup Guide

## Prerequisites

- Docker and Docker Compose installed
- LangBuilder repository cloned
- Terminal access

---

## Step 1: Build OpenWebUI with OAuth Token Forwarding

```bash
# Navigate to project root
cd /path/to/LangBuilder

# Build OpenWebUI image with modified code
docker compose -f docker-compose-integration.yml build openwebui
```

---

## Step 2: Start Keycloak and PostgreSQL

```bash
# Start only Keycloak and database first
docker compose -f docker-compose-integration.yml up -d keycloak postgres

# Wait 20-30 seconds for Keycloak to be ready
docker compose -f docker-compose-integration.yml logs -f keycloak
```

Wait until you see: `Keycloak ... started`

---

## Step 3: Configure Keycloak

### 3.1 Access Keycloak Admin Console

- URL: `http://localhost:8080`
- Username: `admin`
- Password: `admin`

### 3.2 Create Realm

1. Click **"Create Realm"** (top left dropdown)
2. **Realm name:** `company`
3. Click **"Create"**

### 3.3 Create Client: openwebui

1. Go to **Clients** → **"Create client"**
2. **Client ID:** `openwebui`
3. **Client type:** `OpenID Connect`
4. Click **"Next"**
5. **Client authentication:** `ON`
6. Click **"Next"**
7. **Valid redirect URIs:** `http://localhost:8000/oauth/oidc/callback`
8. **Web origins:** `http://localhost:8000`
9. Click **"Save"**
10. Go to **"Credentials"** tab
11. **Copy the Client Secret**

### 3.4 Update Environment Variable

```bash
# Create .env file in project root
echo "OPENWEBUI_CLIENT_SECRET=<paste-your-client-secret-here>" > .env
```

### 3.5 Create Client: langbuilder-api

1. Go to **Clients** → **"Create client"**
2. **Client ID:** `langbuilder-api`
3. **Client type:** `OpenID Connect`
4. Click **"Next"**
5. **Client authentication:** `ON`
6. Click **"Next"**
7. **Valid redirect URIs:** `*`
8. Click **"Save"**

### 3.6 Create Audience Mapper

1. Go to **Clients** → `openwebui`
2. Click **"Client scopes"** tab
3. Click `openwebui-dedicated`
4. Click **"Mappers"** tab
5. Click **"Add mapper"** → **"Configure a new mapper"**
6. Select **"Audience"**
7. Configure:
   - **Name:** `langbuilder-audience`
   - **Included Client Audience:** `langbuilder-api`
   - **Add to ID token:** `OFF`
   - **Add to access token:** `ON`
8. Click **"Save"**

### 3.7 Create Realm Roles

1. Go to **Realm roles** → **"Create role"**
2. Create role: `admin`
3. Click **"Save"**
4. Click **"Create role"** again
5. Create role: `user`
6. Click **"Save"**

### 3.8 Create Test Users

**Admin User:**
1. Go to **Users** → **"Create user"**
2. **Username:** `testadmin`
3. Click **"Create"**
4. Go to **"Credentials"** tab
5. Click **"Set password"**
6. **Password:** `test123`
7. **Temporary:** `OFF`
8. Click **"Save"**
9. Go to **"Role mapping"** tab
10. Click **"Assign role"**
11. Select `admin`
12. Click **"Assign"**

**Regular User:**
1. Go to **Users** → **"Create user"**
2. **Username:** `testuser`
3. Click **"Create"**
4. Go to **"Credentials"** tab
5. Click **"Set password"**
6. **Password:** `test123`
7. **Temporary:** `OFF`
8. Click **"Save"**
9. Go to **"Role mapping"** tab
10. Click **"Assign role"**
11. Select `user`
12. Click **"Assign"**

---

## Step 4: Start All Services

```bash
# Start all services
docker compose -f docker-compose-integration.yml up -d

# Verify all services are running
docker compose -f docker-compose-integration.yml ps
```

Expected output: 5 services running (keycloak, postgres, langbuilder-backend, langbuilder-frontend, openwebui)

---

## Step 5: Create Test Flows in LangBuilder

### 5.1 Access LangBuilder Frontend

- URL: `http://localhost:3000`

### 5.2 Create Flows with Different Access Levels

**Public Flow:**
1. Create a new flow
2. Name: `Public Flow`
3. Leave tags empty or add tag: `public`
4. Save

**Admin-Only Flow:**
1. Create a new flow
2. Name: `Admin Only Flow`
3. Add tag: `group:admin`
4. Save

**User Flow:**
1. Create a new flow
2. Name: `User Flow`
3. Add tag: `group:user`
4. Save

---

## Step 6: Test OAuth Token Forwarding

### 6.1 Test with Admin User

1. Open browser: `http://localhost:8000`
2. Click **"Sign in with Keycloak"**
3. Login with:
   - Username: `testadmin`
   - Password: `test123`
4. Check available models in OpenWebUI
5. **Expected:** Should see ALL flows (Public Flow, Admin Only Flow, User Flow)

### 6.2 Test with Regular User

1. Logout from OpenWebUI
2. Login with:
   - Username: `testuser`
   - Password: `test123`
3. Check available models in OpenWebUI
4. **Expected:** Should see only Public Flow and User Flow
5. **Expected:** Should NOT see Admin Only Flow

---

## Step 7: Verify OAuth Token Forwarding in Logs

```bash
# Check OpenWebUI logs
docker compose -f docker-compose-integration.yml logs openwebui | grep -i "oauth"

# Look for:
# - "Using OAuth access token for user"
# - "Stored OAuth session server-side"

# Check LangBuilder Backend logs
docker compose -f docker-compose-integration.yml logs langbuilder-backend | grep -i "oidc"

# Look for:
# - "OIDC token validated for subject="
```

---

## Troubleshooting Commands

### Rebuild OpenWebUI
```bash
docker compose -f docker-compose-integration.yml build --no-cache openwebui
docker compose -f docker-compose-integration.yml up -d openwebui
```

### Restart Specific Service
```bash
docker compose -f docker-compose-integration.yml restart openwebui
```

### View Real-time Logs
```bash
docker compose -f docker-compose-integration.yml logs -f openwebui
docker compose -f docker-compose-integration.yml logs -f langbuilder-backend
```

### Check Environment Variables
```bash
docker compose -f docker-compose-integration.yml exec openwebui env | grep OAUTH
docker compose -f docker-compose-integration.yml exec langbuilder-backend env | grep OIDC
```

### Full Reset
```bash
# Stop all services
docker compose -f docker-compose-integration.yml down

# Remove volumes (WARNING: deletes all data)
docker compose -f docker-compose-integration.yml down -v

# Start fresh
docker compose -f docker-compose-integration.yml up -d
```

### Check Database Connection
```bash
# PostgreSQL
docker compose -f docker-compose-integration.yml exec postgres psql -U langbuilder -d langbuilder -c "\dt"

# OpenWebUI database (check oauth_session table)
docker compose -f docker-compose-integration.yml exec openwebui ls -la /app/backend/data/
```

---

## Quick Reference

| Service | URL | Credentials |
|---------|-----|-------------|
| Keycloak Admin | http://localhost:8080 | admin / admin |
| OpenWebUI | http://localhost:8000 | testadmin / test123 or testuser / test123 |
| LangBuilder Frontend | http://localhost:3000 | - |
| LangBuilder Backend API | http://localhost:7860/health | - |
| LangBuilder OpenAI API | http://localhost:7860/v1/models | Requires OAuth token |

---

## Files Modified

| File | Purpose |
|------|---------|
| `docker-compose-integration.yml` | OpenWebUI service configured with OAuth forwarding |
| `openwebui/Dockerfile` | Custom build with modified backend code |
| `openwebui/backend/open_webui/utils/oauth.py` | Fixed async/await for token refresh |
| `openwebui/backend/open_webui/routers/openai.py` | OAuth token forwarding implementation |
| `.env` | Contains OPENWEBUI_CLIENT_SECRET |

---

## Expected Behavior

### testadmin (role: admin)
- ✅ Sees all flows regardless of tags
- ✅ Can access flows tagged with `group:admin`
- ✅ Can access flows tagged with `group:user`
- ✅ Can access public flows

### testuser (role: user)
- ✅ Can access flows tagged with `group:user`
- ✅ Can access public flows
- ❌ Cannot access flows tagged with `group:admin`

---

## Clean Up

```bash
# Stop all services
docker compose -f docker-compose-integration.yml down

# Remove all data (optional)
docker compose -f docker-compose-integration.yml down -v

# Remove built images (optional)
docker rmi $(docker images | grep langbuilder | awk '{print $3}')
docker rmi $(docker images | grep openwebui | awk '{print $3}')
```
