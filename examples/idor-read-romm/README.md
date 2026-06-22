# GHSA-5ghc-8wr3-788c

Insecure Direct Object Reference (IDOR) in [RomM](https://github.com/rommapp/romm)
`<= 4.4.0` (`CVE-2025-65096`). `GET /api/collections/{id}` returns a collection
with **no ownership or `is_public` check**:

```python
# backend/endpoints/collections.py
@protected_route(router.get, "/{id}", [Scope.COLLECTIONS_READ])
def get_collection(request: Request, id: int) -> CollectionSchema:
    collection = db_collection_handler.get_collection(id)
    if not collection:
        raise CollectionNotFoundInDatabaseException(id)
    return CollectionSchema.model_validate(collection)   # any user, any collection
```

Any authenticated user (every role holds `collections.read`) can read another
user's **private** collection — name, description, owner id — by iterating the
integer id. The sibling `update_collection` correctly enforces
`collection.user_id != request.user.id`, making the missing check on the read path
unambiguous. Fixed in `4.4.1`.

Sources:

- https://github.com/rommapp/romm/security/advisories/GHSA-5ghc-8wr3-788c
- https://github.com/advisories/GHSA-5ghc-8wr3-788c

## Reproduce

```bash
# DB + cache
docker run -d --name romm-db -e MARIADB_ROOT_PASSWORD=root -e MARIADB_DATABASE=romm \
  -e MARIADB_USER=romm -e MARIADB_PASSWORD=romm -p 127.0.0.1:3307:3306 mariadb:11
docker run -d --name romm-redis -p 127.0.0.1:6380:6379 valkey/valkey:8

git clone https://github.com/rommapp/romm && cd romm && git checkout 4.4.0
brew install libmagic mariadb-connector-c
export PATH="/opt/homebrew/opt/mariadb-connector-c/bin:$PATH"   # so the mariadb python pkg builds
uv sync

# env reused by the migration + the server
mkdir -p /tmp/romm_mock/{database,library,resources,assets,config}
env_vars="ROMM_BASE_PATH=/tmp/romm_mock ROMM_DB_DRIVER=mariadb DB_HOST=127.0.0.1 DB_PORT=3307 \
  DB_NAME=romm DB_USER=romm DB_PASSWD=romm REDIS_HOST=127.0.0.1 REDIS_PORT=6380 \
  ROMM_AUTH_SECRET_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  DISABLE_CSRF_PROTECTION=true DEV_MODE=true"
cd backend
env $env_vars ../.venv/bin/alembic upgrade head
env $env_vars ../.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8001
```

In another terminal from the `nocapsec` repo:

```bash
go run ./examples/idor-read-romm
```

`main.go` bootstraps two RomM users (an admin `owner` and a viewer `attacker`) and
mints a bearer token for each, writing them into a temporary `-authstate` file (RomM
issues short-lived tokens, so they cannot be committed). The engine then has the
**owner** create a private collection named `NOCAPSEC_CANARY_<nonce>` and the
**attacker** (a different session) read it by id. A verified report
(`matched_marker`, `attacker_status: 200`) proves the cross-user read.
