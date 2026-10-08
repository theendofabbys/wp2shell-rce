# wp2shell

Unauthenticated SQL injection scanner and exploit chain for WordPress core,
targeting the REST batch endpoint sink (`CVE-2026-63030` / `CVE-2026-60137`
tracking). Detection, in-band data extraction, and full admin account creation
against affected WordPress 6.8.x – 7.0.x installs.

The tool is a single-file Python 3 script. No dependencies beyond the standard
library.

---

## The vulnerability

WordPress exposes a REST batch endpoint at `/?rest_route=/batch/v1` (also
reachable as `/wp-json/batch/v1`). The endpoint accepts a JSON (or multipart)
envelope containing an array of sub-requests and dispatches them internally.

The dispatch path builds an internal request object from user-supplied
`path` fields and passes query parameters down to the REST controllers. One of
those controllers — `/wp/v2/users` and `/wp/v2/posts/<id>` — accepts an
`author_exclude` parameter that is concatenated into a SQL `WHERE` clause
without going through `$wpdb->prepare()` on the affected versions.

Because the batch dispatcher resolves `path` values before the REST layer
re-validates them, the injection point is reachable **unauthenticated**. The
request never has to clear the `edit_users` capability check that would
normally guard the parameter — the batch layer processes the sub-request
first, and the SQL is assembled before the permission callback returns.

### Injection shape

The parameter is interpolated as:

```sql
... AND user_id NOT IN (<author_exclude>) ...
So a payload of the form:
0) OR (SELECT 1 FROM (SELECT SLEEP(4))x)-- -
closes the IN (...) list, injects a boolean or time primitive, and comments
out the trailing SQL. Stacked queries are not needed; the sink is a single
SELECT and the injection rides inside it.


Affected versions
Range	Status
6.8.0 – 6.8.5	SQLi sink only (no full chain)
6.9.0 – 6.9.4	Full chain (SQLi + row forgery → admin)
7.0.0 – 7.0.1	Full chain



Anything outside those ranges is reported as outside-affected-range. The
scanner still reports vulnerable if the injection actually fires, because
version fingerprints can lie (backports, patches, custom builds).

The full chain

On the full-chain versions the SQLi is not just an oracle — it is a write
primitive into wp_posts. The batch dispatcher will process a nested
sub-request whose author_exclude parameter carries a UNION ALL SELECT
that forges entire rows into the posts table, including rows with
post_type values the attacker controls.

create_admin abuses this:

seed — forge a post containing three [embed] shortcodes pointing at
URLs on the target host. WordPress' oEmbed handler resolves each URL and
writes a cache row in wp_posts with post_type=oembed_cache. Those rows
are the anchor: their IDs are attacker-predictable via the MD5 of
url + serialized_attr.



Poison — forge a customize_changeset row whose post_content is a
serialized nav_menu_item payload. Set its post_parent to one of the
oEmbed cache IDs so the changeset is treated as a child of the cache and
bypasses the edit_theme_options capability gate

Trigger — a second forged post contains an [embed] shortcode pointing
at the poisoned cache URL. Rendering that shortcode walks the changeset,
which instantiates the nav_menu_item object with a user_id field
pointing at an existing administrator.

Escalate — the forged changeset's content is a serialized array whose
user_id key is set to the target admin's ID. The POST /wp/v2/users
sub-request that follows re-uses that changeset state and creates a new
user with roles: ["administrator"] without hitting the
create_users capability check — the batch dispatcher's permission
callback sees the changeset's author (an admin), not the actual requester.

Usage

# scan one target
python3 poc.py https://example.com

# scan a list, JSON output
python3 poc.py -f hosts.txt --json -t 20

# confirm vulnerability and read DB fingerprint
python3 poc.py https://example.com --proof

# full chain — create an admin
python3 poc.py https://example.com --create-admin


Flags:
--create-admin       run the full chain against a confirmed-vulnerable target
--proof              read @@version and current_user() via in-band extraction
-f, --file           file with one target per line
--verbose            detailed request log to stderr
--route {auto,rest-route,wp-json}
--method {auto,boolean,time}
--delivery {auto,json,multipart}
--slot {auto,users,posts-item}
--sleep FLOAT        SLEEP() seconds for the time oracle (default 4.0)
--rounds INT         probes per oracle round (default 3)
--timeout FLOAT      per-request timeout in seconds (default 15.0)
--proxy              HTTP proxy URL
-t, --threads INT    scan concurrency (default 10)
--json               machine-readable output


Requirements

    Python 3.8+

    Standard library only


