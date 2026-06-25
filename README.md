# Google Cloud IAM<br>Architecture, Internals, and Service Account Security
## By Stan Drapkin [2026 June]
### Professional Google Cloud Training Curriculum for Engineers

* **Format:** Self-paced or instructor-delivered technical course
* **Audience:** Software/platform/security engineers with basic cloud literacy (you know what a project, VM, and API key are). No prior Google Cloud IAM-specific knowledge assumed.
* **Tooling used:** `gcloud` CLI, IAM REST API (`v1`/`v2`/`v3`), Cloud Console, Cloud Audit Logs, Policy Analyzer/Troubleshooter

---

## How this course is organized

14 modules, progressing from foundational mental models to production-grade, attacker-aware design. Each module has explicit learning objectives, a time estimate, and prerequisites.
* Modules 1–4 are **Foundation**
* Modules 5–9 are **Core Specialization (Service Accounts)**
* Modules 10–13 are **Advanced/Expert**
* Module 14 is a **Capstone**. After Module 14 you will find the cheat sheet, the decision tree, and an interview question bank.

| # | Module | Level | Time |
|---|--------|-------|------|
| 0 | IAM Orientation | Beginner | 1h |
| 1 | IAM Resource Hierarchy & Mental Model | Beginner | 1.5h |
| 2 | Roles: Basic, Predefined, Custom | Beginner | 2h |
| 3 | Policy Structure & Evaluation Logic | Beginner/Intermediate | 2.5h |
| 4 | Deny Policies & IAM Conditions (CEL) | Intermediate | 2.5h |
| 5 | Service Accounts: Concepts & Lifecycle | Intermediate | 2.5h |
| 6 | Service Account Internals: Tokens, JWTs, OAuth2 | Advanced | 3.5h |
| 7 | Keys vs. Keyless Auth – Risk Engineering | Advanced | 2.5h |
| 8 | Impersonation Internals & Delegation Chains | Advanced | 3h |
| 9 | Cross-Project & Cross-Org Access Patterns | Advanced | 2.5h |
| 10 | Workload Identity & Workload Identity Federation | Advanced/Expert | 3.5h |
| 11 | Audit Logging, Detection & Privilege Escalation Paths | Expert | 3h |
| 12 | Secret Management vs. Service Accounts | Expert | 1.5h |
| 13 | Production Architecture Patterns & Real-World Breaches | Expert | 2.5h |
| 14 | Capstone: Designing a Secure Multi-Service Platform | Expert | 2h |

---

## Module 0 – Orientation: The IAM Mental Model

Before any syntax, internalize one sentence: **GCP IAM answers exactly one question – "does principal P have permission Q on resource R, at this moment, given this context?"** Every mechanism in this course (roles, bindings, conditions, deny rules, impersonation, federation) is machinery built around answering that single question correctly, quickly, and at the scale of an organization with thousands of resources.

Three nouns recur constantly and must not be conflated:

- **Principal** – "who": a Google Account (human), a Google group, a service account, a Workspace/Cloud Identity domain, or (with Workload Identity Federation) an external federated identity. Principals are *who is asking*.
- **Permission** – "what action": a fine-grained string like `compute.instances.delete` or `bigquery.tables.getData`. Permissions are never granted directly to principals – they are bundled into **roles**. A GCP **role** is a named set of permissions that determines what actions a Principal (a user, group, or service account) can perform on GCP resources.
- **Resource** – "on what": anything in the resource hierarchy, from the Organization node down to an individual Cloud Storage object or Pub/Sub topic.

A **Role Binding** is a tuple of `(1 specific role, N Principals)`. Each Role Binding contains exactly 1 role and zero or more members (principals) bound to that role. An example of a Role Binding is:
> (**role**: `roles/storage.objectViewer`, **members**: `alice@example.com, bob@example.com`)
```
Binding
├── role     (exactly one)
└── members  (zero or more)
```

Role Bindings can also be **conditional**:
```
Binding
├── role       (1)
├── members    (N)
└── condition  (optional)
```
An example of a **conditional Role Binding** which grants temporary access:
```YAML
- role: roles/storage.objectViewer
  members:
  - user:alice@example.com
  condition:
    expression: request.time < timestamp("2027-01-01T00:00:00Z")
```

Since each Role Binding defines 1 role only, how do we grant multiple roles? A set of Role Bindings is called an **IAM Policy** in GCP. The YAML version of a sample **IAM Policy Schema** with 2 Role Bindings is:
```YAML
bindings:
- role: roles/storage.objectViewer
  members:
  - user:alice@example.com
  - user:bob@example.com

- role: roles/storage.admin
  members:
  - user:charlie@example.com
```

IAM Policy in GCP does not exist by itself – it must be stored on (attached to) a GCP Resource. Effectively, IAM Policy is always a property of some GCP Resource. Thus GCP IAM is:
```
Resource
  └── IAM Policy
       └── Bindings
             ├── Role A -> Members...
             ├── Role B -> Members...
             └── Role C -> Members...
```

```
Project A
   └── IAM Policy

Bucket B (Google Cloud Storage/GCS)
   └── IAM Policy

Dataset C (BigQuery)
   └── IAM Policy
```

GCP Role Bindings have historically been `allow` policies, and every Role Binding in an IAM Policy is an `allow` grant. Later, GCP also added `deny` IAM Policies:
```
Resource
 ├── Allow IAM Policy
 └── Deny IAM Policy
 ```

`deny` IAM policy has a different structure (contains deny-rules instead of allow-bindings):
```
Deny IAM Policy
   └── Deny Rules
         ├── Principals
         ├── Permissions
         └── Exceptions
```
Note that `deny` IAM policies do not use **Roles** (sets of Permissions), and typically reference permissions directly (i.e. you directly deny specific Permissions and Principals, not Roles). An individual IAM Role Binding is never marked as `allow` or `deny` : a Role Binding is always an `allow` grant. The `deny` rules are captured by the separate Deny IAM Policy which is also attached to a Resource:
```
Resource
 ├── Allow Policy
 │      └── Bindings
 │            ├── Role A -> Members
 │            └── Role B -> Members
 │
 └── Deny Policy
        └── Deny Rules
              ├── Principals
              ├── Permissions
              └── Exceptions
```

A sample IAM Deny Policy structure and YAML:
```
DenyPolicy
 ├── displayName
 └── rules[]
       ├── description
       └── denyRule
             ├── deniedPrincipals[]
             ├── exceptionPrincipals[]
             ├── deniedPermissions[] ← IAM v2 format: SERVICE_FQDN/RESOURCE.ACTION
             └── denialCondition (CEL expression)
 ```
 ```YAML
 displayName: "Deny deletion of production GCS objects"
rules:
  - description: "Block object deletion in production bucket"
    denyRule:
      deniedPrincipals:
        - principalSet://goog/public:all
      exceptionPrincipals:
        - principalSet://goog/group/storage-admins@example.com
      deniedPermissions:
        - "storage.googleapis.com/objects.delete"
      denialCondition:
        title: "Protect production prefix"
        expression: "resource.name.startsWith('projects/_/buckets/prod-bucket/objects/')"

  - description: "Prevent accidental bucket deletion"
    denyRule:
      deniedPrincipals:
        - principalSet://goog/public:all
      exceptionPrincipals:
        - principalSet://goog/group/org-admins@example.com
      deniedPermissions:
        - "storage.googleapis.com/buckets.delete"
 ```

Deny IAM Policy Principals are expressed as "principal sets":
```
principalSet://goog/group/storage-admins@example.com
principalSet://goog/public:all
principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/subject/...
```

IAM Policy condition expressions (both `allow` and `deny` kinds) use **[Common Expression Language](https://docs.cloud.google.com/iam/docs/conditions-overview#cel) (CEL)**. Exceptions in deny-policies are first-class and selectively override `deny` rules.

The **effective policy** for a resource is the union of its own allow policy plus every allow policy inherited from ancestors in the hierarchy, minus anything blocked by deny policies. Mental Model:
```
IF match_any(DENY_POLICY.rules)
    AND NOT in exceptions
THEN DENY

ELSE IF match_any(ALLOW_POLICY.bindings)
THEN ALLOW

ELSE DENY
```
> Note: this omits [Principal Access Boundary](https://docs.cloud.google.com/iam/docs/principal-access-boundary-policies) (PAB) policies, covered in full in §3.2

---

## Module 1 – IAM Resource Hierarchy & Mental Model

* **Learning objectives:** Explain the 4-level resource hierarchy and why it exists; describe policy inheritance precisely (not loosely); identify where a given access grant "lives" and why; understand propagation latency and its operational implications.
* **Prerequisites:** None beyond knowing what a GCP project is.

### 1.1 The hierarchy

```
Organization (organizations/123456789)
   └── Folder (folders/111)              [optional, can nest folders inside folders]
         └── Folder (folders/222)
               └── Project (projects/my-project-id)
                     └── Resource (e.g. compute.googleapis.com/projects/.../instances/vm-1)
```

- **Organization** – the root node, normally tied to a Cloud Identity or Google Workspace domain. Created once per company (or business unit, in some designs). If you don't have an Organization, your projects are "orphan" projects floating with no common ancestor – common in personal accounts or early-stage startups, and a frequent source of governance pain later, because there is no single node to attach an org-wide allow or deny policy to.
- **Folder** – an optional grouping node used to mirror business structure: business units, environments (`prod`/`staging`/`dev`), or compliance boundaries. Folders can nest arbitrarily deep (practical hierarchies are rarely more than 3–4 levels). Folders exist almost entirely to be a unit of **policy and Org Policy application** – a way to say *"everything under `folder/prod` inherits these guardrails"* without repeating bindings on every project.
- **Project** – the primary unit of billing, quota, API enablement, and resource ownership. Nearly all resources (VMs, buckets, service accounts, BigQuery datasets) live inside exactly one project.
- **Resource** – the leaf level: individual GCP objects. Critically, *not all resource types support IAM policies directly* – many services only support policy attachment at the project level and inherit from there (e.g., classic Compute Engine instances do not have their own IAM policy; the *service account attached to* a VM does, and so does the project). Others – Cloud Storage buckets, BigQuery datasets/tables, Pub/Sub topics, KMS keys, individual Service Accounts – support **resource-level IAM policies** of their own.

### 1.2 Inheritance: precise mechanics, not folklore

The informal phrase "permissions flow downhill" is true but underspecified. The precise rule:

> The **effective allow policy** on any resource R is the **union (logical OR)** of every Role Binding in the allow policy attached directly to R, plus every role binding in the allow policy attached to every ancestor of R, all the way up to the Organization node.

Important consequences that engineers routinely get wrong:

1. **You cannot subtract via inheritance.** If `user:alice@example.com` is bound to `roles/editor` at the Organization, no project or folder underneath can *remove* that grant by omission. The only mechanism to block an inherited allow grant is a **deny policy** (Module 4). `allow` policies are purely additive across the hierarchy.
2. **Inheritance is policy-level, not permission-level intersection.** People sometimes assume access requires permission at every level ("AND" semantics, like AWS SCPs intersecting with IAM). GCP allow-policy inheritance is **OR/union** semantics: a single qualifying binding *anywhere* in the ancestor chain is sufficient.
3. **Resource-level policies do not override ancestor grants – they add to them.** Setting an empty IAM policy on a bucket does not strip access granted at the project or org level. This is the single most common *"why can't I lock this bucket down"* support ticket.
4. **Some resource types restrict inheritance scope deliberately.** A few GCP services implement custom hierarchical rules (for example, some BigQuery dataset-level controls or VPC Service Controls perimeters behave differently from plain IAM inheritance). When something looks like it's "not inheriting as expected," check whether the resource type has product-specific access semantics layered on top of base IAM.

### 1.3 Propagation latency

IAM is a globally distributed system, not a single transactional database. After a `setIamPolicy` call succeeds, the change is **strongly consistent for reads through the IAM API itself**, but **propagation to all the enforcement points across Google's infrastructure (caches in every regional/zonal service backend) is eventually consistent**, with Google's [documented guidance](https://docs.cloud.google.com/iam/docs/access-change-propagation) being to expect **up to ~7 minutes**, occasionally longer under load, before a policy change is reflected everywhere a permission check happens. Operational implications:

- Automation that does `grant role → immediately call API requiring that role` should retry with backoff, not assume instant effect.
- Revoking access (e.g., during incident response) should not be assumed instantaneous either – pair IAM revocation with key/credential invalidation and, for sensitive cases, disabling the principal outright.
- This is also why **Cloud Console "Test changes"/Policy Simulator and Policy Troubleshooter** evaluate based on the *currently committed* policy, not a hypothetically-propagated one – useful for design-time verification, not real-time incident timing.

### 1.4 `gcloud`: walking the hierarchy

```bash
# View the org you belong to
gcloud organizations list

# List folders under an org
gcloud resource-manager folders list --organization=123456789012

# List projects under a folder
gcloud projects list --filter="parent.id=111111111111 AND parent.type=folder"

# Get the allow policy at any level
gcloud organizations get-iam-policy 123456789012
gcloud resource-manager folders get-iam-policy 111111111111
gcloud projects get-iam-policy my-project-id

# Ancestry of a single project – critical for "why does this principal have access" debugging
gcloud projects get-ancestors my-project-id
```

### 1.5 Common pitfall

**Orphaned projects with Owner granted to individuals.** Projects created outside an Organization (personal Gmail accounts, or organizations not yet using Cloud Identity) have no folder/org ancestor, so there's no central place to enforce guardrails, no org-level deny policies apply, and Org Policy constraints (which only apply within an Organization) don't exist at all. Migrating such projects into an Organization later is possible but operationally nontrivial – plan your org structure before scaling, not after.

---

## Module 2 – Roles: Basic, Predefined, Custom

* **Learning objectives:** Differentiate the 3 role classes precisely; understand permission/role relationship and why permissions are never granted directly; design custom roles correctly, including launch stages and permission support tiers.
* **Prerequisites:** Module 1.

### 2.1 What a role actually is

A **role** is a named, versioned bundle of **permissions**. A permission has the canonical form `service.resource.verb` – e.g. `storage.objects.create`, `iam.serviceAccounts.actAs`, `compute.instances.setMetadata`. There is no way to bind a permission directly to a principal; you always bind a **role**, and the principal effectively receives the union of permissions in every role bound to them (at every level of the hierarchy that applies).

### 2.2 Basic roles (legacy)

`roles/owner`, `roles/editor`, `roles/viewer` (plus `roles/browser`). These predate the predefined-role system and grant **thousands of permissions across nearly every service in the project**, including, critically, `roles/editor` granting the ability to act as most service accounts in many configurations and to modify nearly all resources. They are project-wide, blunt, and **explicitly discouraged by Google for production use** – they remain mostly for backward compatibility and quick prototyping. **The most consequential mistake new GCP teams make is leaving humans or, worse, service accounts bound to `roles/editor` because it "just works."** A service account with `roles/editor` is functionally close to a master key for the entire project.

### 2.3 Predefined roles

Curated, Google-maintained, service-specific roles intended to express common job functions at reasonable granularity – e.g. `roles/compute.instanceAdmin.v1`, `roles/storage.objectViewer`, `roles/bigquery.dataEditor`, `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountTokenCreator`. Google adds permissions to predefined roles over time as new features ship (this is a deliberate design choice – predefined roles are "maintained" so they continue covering the full surface of a service), which has a real security implication: **the effective permission set of a predefined role binding can silently grow over time without any action from you.** This is one of the arguments for custom roles in high-sensitivity environments – you control exactly which permissions are present and when they change.

Naming convention worth internalizing: roles ending in `.viewer` are read-only; `.editor` (service-scoped, e.g. `roles/pubsub.editor`) allows mutating existing resources but typically not IAM policy changes or deletion of the parent resource; `.admin` typically includes full control including IAM policy management on that resource type. Always read the actual permission list (`gcloud iam roles describe`) rather than assuming from the name – naming is a strong convention, not a guarantee.

### 2.4 Custom roles

Custom roles let you assemble an arbitrary set of permissions under one role name, created at the **project** or **organization** level (project-level custom roles do not count against the org-level role quota, and are scoped only to that project's resources). Key mechanics:

- **Launch stage**: `ALPHA`, `BETA`, `GA`, `DEPRECATED`, `DISABLED`. This is metadata for your own change-management process – GCP does not restrict usage based on stage, but tooling and audits often gate on it (e.g., "don't promote ALPHA custom roles to prod bindings").
- **Permission support level**: not every permission can be added to a custom role. Each permission is tagged internally as `SUPPORTED`, `TESTING`, or `NOT_SUPPORTED` for custom role inclusion. Permissions Google considers too sensitive, too tightly coupled to other permissions, or not yet stabilized may be excluded – `gcloud iam list-testable-permissions` against a resource tells you what's actually usable.
- Custom roles **do not auto-update** the way predefined roles do – this is the entire point. You own the lifecycle, including the obligation to revisit them when new permissions for a feature you rely on are introduced.
- Custom roles are commonly built by **starting from a predefined role and trimming it** – this is both the recommended workflow and the place where IAM Recommender / Policy Analyzer earn their keep (Module 11) by showing which granted permissions were never actually used in the last 90 days.

### 2.5 `gcloud` examples

```bash
# Inspect a predefined role's actual permissions (don't trust the name)
gcloud iam roles describe roles/iam.serviceAccountTokenCreator

# List permissions usable in a custom role on a given resource
gcloud iam list-testable-permissions \
  //cloudresourcemanager.googleapis.com/projects/my-project-id

# Create a custom role scoped to project, derived by trimming a predefined role
gcloud iam roles create bqReadOnlyAnalyst \
  --project=my-project-id \
  --title="BigQuery Read-Only Analyst" \
  --description="Read query data only, no job creation, no table mutation" \
  --permissions=bigquery.datasets.get,bigquery.tables.get,bigquery.tables.getData \
  --stage=GA
```

Example custom role definition file (YAML), the form you'd commit to version control/Terraform:

```yaml
title: "bqReadOnlyAnalyst"
description: "Read query data only, no job creation, no table mutation"
stage: "GA"
includedPermissions:
  - bigquery.datasets.get
  - bigquery.tables.get
  - bigquery.tables.getData
```

### 2.6 Pitfall: "least privilege" custom roles that aren't

A custom role with a small *count* of permissions is not automatically least-privilege. `iam.serviceAccounts.actAs` alone, for instance, is a single permission but – combined with the right deploy permission on a compute resource – is a privilege-escalation primitive (Module 11). Evaluate roles by **what they enable in combination with the rest of a principal's grants**, not permission count.

---

## Module 3 – Policy Structure & Evaluation Logic

* **Learning objectives:** Read and write raw allow-policy JSON/YAML; state the full evaluation algorithm Google runs on every permission check, in order; understand policy versions (`bindings` schema v1 vs v3 with conditions); use the official troubleshooting tools.
* **Prerequisites:** Modules 1–2.

### 3.1 Anatomy of an allow policy

An allow policy is a JSON/YAML document with this shape:

```json
{
  "version": 3,
  "bindings": [
    {
      "role": "roles/storage.objectViewer",
      "members": [
        "user:alice@example.com",
        "group:data-readers@example.com",
        "serviceAccount:ingest-sa@my-project.iam.gserviceaccount.com"
      ]
    },
    {
      "role": "roles/storage.objectAdmin",
      "members": [
        "serviceAccount:pipeline-sa@my-project.iam.gserviceaccount.com"
      ],
      "condition": {
        "title": "business-hours-only",
        "description": "Only allow writes during business hours UTC",
        "expression": "request.time.getHours('UTC') >= 6 && request.time.getHours('UTC') <= 18"
      }
    }
  ],
  "etag": "BwXhqDvz5anExample=",
  "auditConfigs": []
}
```

Field semantics:

- **`role`** – full role resource name (`roles/...` for predefined/basic, `projects/P/roles/...` or `organizations/O/roles/...` for custom).
- **`members`** – *principal* identifiers (the field is still named `members` for historical API-compatibility reasons even though "principal" is the current terminology). Prefixes matter and are part of the contract: `user:`, `serviceAccount:`, `group:`, `domain:`, `principal://` and `principalSet://` (for Workforce/Workload Identity Federation subjects), `deleted:serviceAccount:...?uid=...` (a tombstoned reference left behind after a service account deletion – see Module 5), `allUsers` (literally anyone on the internet, unauthenticated), `allAuthenticatedUsers` (anyone with *any* Google account, not scoped to your org – almost never what you want).
- **`condition`** – optional CEL boolean expression; a binding with a condition only applies when the expression evaluates true at request time (Module 4).
- **`etag`** – concurrency-control token. **This is not optional in practice.** Every `setIamPolicy` should be preceded by a `getIamPolicy` and should echo back the etag; omitting this invites a classic read-modify-write race where two concurrent admins each wipe out the other's change. `gcloud projects add-iam-policy-binding` handles this for you internally; raw API/Terraform usage must handle it explicitly.
- **`version`** – policy schema version. **Version 1** policies cannot contain conditions at all. **Version 3** is required for any binding using a `condition` block, and once a policy contains a conditional binding, all reads/writes against it must explicitly request `version=3`, or the API will reject/strip the conditional bindings. This trips up a lot of home-grown automation that doesn't pass `--policy-version=3` (gcloud) or `optionsRequestedPolicyVersion: 3` (REST).

### 3.2 The full evaluation algorithm

When any GCP service receives a request and needs to authorize it, it (logically) executes a check against IAM with this lookup, in this order – this is the precise algorithm, not an approximation:

1. **Identify the principal** making the request (resolved from the credential presented – OAuth2 access token, ID token, or internal service identity – see Module 6 for how that identity is established for service accounts specifically).
2. **Identify the permission(s)** required for the requested operation on the target resource (every API method maps to one or more required permissions; this mapping is internal to each service and partially documented per-method, e.g. in "Required permissions" sections of API reference docs).
3. **Principal access boundary policies**, if any are attached, are evaluated first – these are an organization-level guardrail mechanism that restricts which resources a principal's credentials can be used against *at all*, independent of any allow/deny grant. If a PAB policy doesn't permit the resource, evaluation stops here with a deny.
4. **Deny policies** are evaluated next. IAM gathers every deny policy attached to the resource and to all its ancestors. If any applicable deny rule (not excepted by an exception principal/permission/condition) covers the requested principal and permission, the request is **denied immediately, full stop** – no allow policy, no matter how permissive, can override this. This is the entire reason deny policies exist: to express organization-wide hard limits that survive accidental or malicious over-granting of allow roles, including against principals holding `roles/owner`.
5. **Allow policies** are evaluated only if step 4 didn't deny. IAM gathers every allow policy attached to the resource and to all its ancestors (the union from Module 1), and checks whether **any single binding** grants a role containing the required permission **for this principal**, where, if the binding has a condition, **the condition evaluates to true** for the current request context (time, resource attributes, request attributes).
6. If at least one such binding is found and not blocked by step 4, **access is granted**. Otherwise, **access is denied** (the default in IAM is implicit-deny; there is no such thing as "no opinion").

A useful way to phrase steps 4–5 together for memory: **"deny wins, allow is a union, and the default is no."**

### 3.3 Policy Troubleshooter and Policy Analyzer

These are not optional extras – for any nontrivial environment, manually reasoning through the hierarchy by eye does not scale, and Google ships purpose-built tools:

```bash
# Why can/can't this principal do this on this resource? (point-in-time troubleshooting)
gcloud policy-troubleshoot iam \
  //compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/vm-1 \
  --principal-email=alice@example.com \
  --permission=compute.instances.delete

# Org-wide query: who has a specific permission anywhere under this scope?
gcloud asset search-all-iam-policies \
  --scope=organizations/123456789012 \
  --query="policy:roles/owner"
```

The Policy Troubleshooter output explicitly walks the same algorithm above – listing every relevant binding, every relevant deny rule, and the resulting access state – and is the single best tool for *"why does/doesn't X work"* debugging instead of guessing.

### 3.4 Common pitfalls

- **Forgetting `allAuthenticatedUsers` means "any Google account on Earth," not "any account in my org."** Several public data-exposure incidents have stemmed from this exact misunderstanding on Cloud Storage buckets.
- **Treating `roles/editor` as a safe default "just to get unblocked."** It nearly always over-grants relative to actual need, and because basic roles predate fine-grained permissions, their exact boundary is harder to reason about than a predefined or custom role.
- **Not requesting policy version 3 in automation**, causing conditional bindings to silently disappear from API responses or fail to apply on write.
- **Assuming resource-level deny on a bucket overrides a project-level allow** without checking the deny policy actually targets the right resource scope and permission set – deny policies use **IAM v2 permission identifiers** (`SERVICE_FQDN/RESOURCE.ACTION`, e.g. `storage.googleapis.com/objects.create`), a different string format from v1 role-binding permissions (`storage.objects.create`), and not every permission is deny-policy-eligible (Module 4 covers this).

---

## Module 4 – Deny Policies & IAM Conditions (CEL)

* **Learning objectives:** Write correct deny policies including exceptions; write and debug CEL condition expressions; know which attributes are available at evaluation time; understand the limits of both mechanisms.
* **Prerequisites:** Module 3.

### 4.1 Deny policies – structure

Deny policies are a **separate API object type** from allow policies (managed via the IAM v2 `policies` API / `gcloud iam policies`, not `setIamPolicy`), attached to a resource via an "attachment point," most commonly an org, folder, or project. A resource can have multiple deny policies attached (the platform allows a meaningfully large number per resource – in the high hundreds as of recent documentation – but treat *"design for a small number of clear, well-documented guardrails"* as the actual best practice regardless of the technical ceiling). Structure:

```json
{
  "displayName": "block-sa-key-creation-org-wide",
  "rules": [
    {
      "denyRule": {
        "deniedPrincipals": ["principalSet://goog/public:all"],
        "exceptionPrincipals": ["principalSet://goog/group/break-glass-admins@example.com"],
        "deniedPermissions": ["iam.googleapis.com/serviceAccountKeys.create"],
        "denialCondition": {
          "expression": "resource.matchTag('environment', 'prod')"
        }
      }
    }
  ]
}
```

```bash
gcloud iam policies create block-sa-key-creation \
  --attachment-point="cloudresourcemanager.googleapis.com/organizations/123456789012" \
  --kind="denypolicies" \
  --policy-file=deny-sa-keys.json
```

Key mechanics worth internalizing:

- **Permission format differs from allow policies.** Deny policies use IAM v2 permission identifiers: `SERVICE_FQDN/RESOURCE.ACTION` (e.g. `iam.googleapis.com/serviceAccountKeys.create`), not the v1 dotted form used in role bindings. Not every permission is eligible for use in a deny rule – Google publishes the supported list, and it skews toward high-impact administrative actions (role management, key creation, policy mutation) rather than every read/write permission in every service.
- **Wildcards via "permission groups."** `SERVICE_FQDN/RESOURCE.*` denies every verb on a resource type; `SERVICE_FQDN/*.*` denies an entire service; `SERVICE_FQDN/*.VERB` denies a verb across a service. These wildcard groups automatically pick up **future** permissions matching the pattern, which is a deliberate "secure by default against drift" design – but also means you should audit what a wildcard rule actually expands to before trusting it blindly in a sensitive environment.
- **Exceptions, not allow-overrides.** `exceptionPrincipals`/`exceptionPermissions` carve out specific principals or permissions from a deny rule. This is the **only sanctioned way** to make a deny rule non-absolute for certain actors (e.g., a break-glass admin group) – there is no separate *"allow takes precedence"* mechanism; exceptions are part of the deny rule itself.
- **Conditions on deny rules** use the same CEL subset as allow-policy conditions (4.2 below), commonly keyed off resource tags (e.g., only deny in resources tagged `environment=prod`) so the same rule set can be relaxed in dev/staging without separate policy documents.
- **Evaluation precedence, restated precisely:** within step 4 of the Module 3 algorithm, if *any* applicable deny rule across the resource and its ancestors covers the principal+permission and is not excepted, the request is denied – **even if the principal holds `roles/owner`.** This is the core value proposition: deny policies are an org's last line of defense against over-granted allow roles, including against humans who accumulated more access than intended over time.

Visualizing IAM Policy evaluation precedence:
<img alt="IAM Policy evaluation precedence" src="https://github.com/user-attachments/assets/cf50af2a-4211-4f57-b676-f31909779565" />


### 4.2 IAM Conditions: CEL fundamentals

IAM Conditions let a single role binding apply only when a boolean **Common Expression Language (CEL)** expression evaluates true, using a deliberately restricted subset of CEL with a fixed set of context variables populated by Google at evaluation time:

| Variable | Type | Example use |
|---|---|---|
| `request.time` | Timestamp | Temporary/time-boxed access: `request.time < timestamp("2026-12-31T00:00:00Z")` |
| `resource.name` | String | Scope a grant to specific resource name patterns |
| `resource.type` | String | Restrict by resource type, e.g. only `storage.googleapis.com/Bucket` |
| `resource.service` | String | Restrict by service |
| `destination.ip`, `origin.ip` | String (some services) | Network-origin-based conditions, service-dependent |
| `resource.matchTag('ns/key','value')` | bool | Tag-based conditions – the modern way to scope by environment/team without rewriting bindings as resources are tagged |

Two condition styles dominate real usage:

1. **Time-bound access** (a textbook least-privilege pattern for incident response / temporary elevated access):

```bash
gcloud projects add-iam-policy-binding my-project-id \
  --member="user:oncall-engineer@example.com" \
  --role="roles/compute.admin" \
  --condition='expression=request.time < timestamp("2026-06-20T00:00:00Z"),title=temp-incident-access,description=Expires after incident window'
```

2. **Resource-attribute-bound access** – granting a role only over resources matching a name prefix or tag, common for multi-tenant or per-team project structures where you don't want to fragment IAM bindings per resource:

```json
{
  "role": "roles/storage.objectAdmin",
  "members": ["serviceAccount:team-a-sa@my-project.iam.gserviceaccount.com"],
  "condition": {
    "title": "team-a-bucket-scope",
    "expression": "resource.name.startsWith('projects/_/buckets/team-a-')"
  }
}
```

### 4.3 What conditions cannot do

Conditions only gate **whether a binding applies**; they cannot express things like rate limiting, multi-factor confirmation, or cross-request state (CEL evaluation here is stateless and per-request). They also cannot be used to *broaden* access beyond what the role already grants – a condition is purely a restrictor on an existing binding, never an additive mechanism. And critically: **a condition on an allow binding only narrows that one binding** – it does nothing to other unconditional bindings elsewhere in the hierarchy that might grant the same permission without restriction. If you intend a hard boundary, you usually want it expressed as (or backed by) a **deny policy**, not solely as a condition on one allow binding, precisely because allow-policy union semantics mean any other unconditional grant elsewhere wins.

### 4.4 Common pitfalls

- **Conditional grants that "don't work"** are very often a `--policy-version=3` omission (Module 3.1) rather than a CEL syntax error.
- **Relying on a time-boxed condition as your *only* control for temporary access**, with no follow-up process to actually remove the binding or verify it expired as intended – expired conditions stop granting access but the binding entry remains in the policy until explicitly deleted, which clutters audits and can mislead a reviewer scanning bindings without checking each condition.
- **Writing deny rules against v1-style permission strings** (`compute.instances.delete` instead of `compute.googleapis.com/instances.delete`) – these silently fail to match anything, giving a false sense of protection.

---

# Part II – Service Accounts

## Module 5 – Service Accounts: Concepts & Lifecycle

* **Learning objectives:** Define a service account precisely and distinguish it from users/groups; enumerate the SA types Google creates automatically vs. ones you create; trace the full lifecycle including the delete/undelete window and its implications; understand the dual nature of a service account as both a principal and a resource.
* **Prerequisites:** Modules 1–4.

### 5.1 What a service account is, precisely

A **service account (SA)** is an identity intended to represent a **workload** (a program, VM, container, function, pipeline) rather than a human. Technically, a service account is a special kind of **Google account** that does not have a password and cannot log in through a normal browser-based consent flow – its only way of "authenticating" is by exercising delegated credentials (tokens, keys, or impersonation grants), all of which trace back to cryptographic proof of identity rather than a human-memorized secret.

The critical conceptual distinction engineers must hold:

| | User account | Group | Service account |
|---|---|---|---|
| Represents | A specific human | A collection of users/SAs | A workload/application |
| Authenticates via | Password/SSO/MFA, interactive consent | N/A (not a login identity, just a binding aggregator) | Tokens minted via OAuth2/JWT flows, or impersonation |
| Can be granted roles | Yes | Yes (applies to all members) | Yes |
| Can itself be a *resource* with its own IAM policy | No | No | **Yes** – this is the dual nature, see 5.2 |
| Typical lifecycle owner | HR/identity provider | Identity team | Engineering team owning the workload |
| Has a long-term secret by default | No (uses federated/SSO auth) | N/A | Not necessarily – attached-identity and impersonation flows need none; keys are opt-in and discouraged |

A common beginner error is treating a service account like "a service's password" – a single static secret to be created once and pasted into config. The mature model is the opposite: **a service account is an identity that should, by default, never need a long-lived secret at all**, because GCP provides multiple keyless mechanisms (attached identity, impersonation, Workload Identity Federation) to mint short-lived credentials on demand.

### 5.2 The dual nature: principal AND resource

This is the **single most important structural fact about service accounts** and the source of a large fraction of IAM confusion:

1. **As a principal**, a service account can be the `member`/`serviceAccount:` entry in a role binding on *some other* resource – e.g., "this SA can read this GCS bucket." This is identical in shape to granting a human a role.
2. **As a resource**, a service account *itself* has its own IAM policy (`gcloud iam service-accounts get-iam-policy`), governing **who is allowed to do things to or as this SA** – e.g., who can attach it to a VM, who can impersonate it, who can delete it, who can manage its keys. Roles relevant here include `roles/iam.serviceAccountUser` (the `iam.serviceAccounts.actAs` permission – lets a principal *attach* the SA to a resource they're creating, like a VM or Cloud Function, so that resource runs as that SA), `roles/iam.serviceAccountTokenCreator` (lets a principal mint short-lived credentials *as* the SA – true impersonation, Module 8), `roles/iam.serviceAccountKeyAdmin` (lets a principal create/list/delete JSON keys for the SA), and `roles/iam.serviceAccountAdmin` (full lifecycle management of the SA object itself – create, disable, delete – but notably *not* automatically the ability to impersonate it or act as it).

Engineers frequently conflate `serviceAccountUser` (attach-to-resource) with `serviceAccountTokenCreator` (mint-credentials-for). They are different permissions solving different problems and **both are independently dangerous in different ways** (Module 11 covers exactly how each becomes a privilege-escalation primitive).

### 5.3 Types of service accounts you'll encounter

- **User-managed service accounts** – the ones you create explicitly. Email format: `SA_NAME@PROJECT_ID.iam.gserviceaccount.com`. Up to 100 characters total, name portion 6–30 characters, lowercase alphanumeric and hyphens.
- **Default service accounts**, created automatically when you enable certain APIs:
  - Compute Engine default SA – `PROJECT_NUMBER-compute@developer.gserviceaccount.com`, historically granted `roles/editor` on the project by default (a long-standing point of criticism; current console flows nudge you to remove this or use a scoped SA instead, but legacy projects often still carry it).
  - App Engine default SA – `PROJECT_ID@appspot.gserviceaccount.com`.
- **Google-managed service agents** – created and used internally by Google services to perform actions on your behalf (e.g., GKE's service agent managing load balancers, Cloud Build's service agent). Format: `service-PROJECT_NUMBER@gcp-sa-SERVICENAME.iam.gserviceaccount.com`. You generally should not delete or heavily restrict these without understanding exactly what breaks – many managed services silently rely on their service agent retaining specific roles.

### 5.4 Lifecycle, precisely

```bash
# Create
gcloud iam service-accounts create ingest-pipeline-sa \
  --project=my-project-id \
  --display-name="Ingest Pipeline SA" \
  --description="Used by Dataflow ingest job, prod only"

# Grant it permission to act on a resource (as a principal)
gcloud projects add-iam-policy-binding my-project-id \
  --member="serviceAccount:ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com" \
  --role="roles/bigquery.dataEditor"

# Grant a human/team permission to use it (acting on the SA as a resource)
gcloud iam service-accounts add-iam-policy-binding \
  ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com \
  --member="group:data-eng@example.com" \
  --role="roles/iam.serviceAccountTokenCreator"

# Disable (reversible – credentials minted against it stop working immediately,
# but the object and its bindings remain, ready to re-enable)
gcloud iam service-accounts disable ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com

# Delete (soft-delete – 30-day undelete window)
gcloud iam service-accounts delete ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com

# Undelete within the window
gcloud iam service-accounts undelete UNIQUE_ID --project=my-project-id
```

Lifecycle facts that matter operationally:

- **Disabling is the correct first response** to a suspected-compromised SA in most cases, not deleting – it's instantly reversible, immediately cuts off new token minting and the use of existing keys, and preserves the object (and its role bindings/audit trail) for investigation. Deletion is appropriate once you're certain the SA should never be used again.
- **Deletion has a 30-day soft-delete window** during which `undelete` restores the exact same SA, including its unique numeric ID and existing IAM bindings.
- **After 30 days (or for any SA recreated under the same name without undeleting), the identity is gone for good.** A new SA created with the *same email string* gets a **different unique ID** internally – any IAM bindings that referenced the old SA become orphaned `deleted:serviceAccount:NAME@PROJECT.iam.gserviceaccount.com?uid=123...` entries that no longer resolve to anything live, and the new SA starts with *zero* of the old grants. This is a frequent production surprise: "we recreated the SA with the same name and now nothing works" – because IAM bindings are keyed to the immutable unique ID under the hood, not the human-readable email string, even though the email string is what's displayed.
- **Service account quotas** are project-scoped. The default per-project limit used to be 100, but is now dynamic and raisable via support request. SA count limits are relevant when designing patterns that mint one SA per microservice or per tenant at scale; at high tenant counts this nudges architectures toward Workload Identity Federation or per-tenant impersonation rather than literally one persistent SA object per tenant. You can search for `Service Account Count` in your project's IAM/"Quotas & System Limits".

### 5.5 When (and when not) to use a service account

Use a service account when a **non-human workload** needs to call GCP APIs or be authenticated to another service: a VM, container, Cloud Function, CI/CD job, on-prem application, or another cloud's workload. Do **not** use a service account as a substitute for proper human authentication (e.g., sharing one SA's key among a team of analysts "to make BigQuery easier") – this destroys individual accountability in audit logs (every action shows the SA, not the human), which is precisely the property audit logging exists to provide, and is one of the most common audit findings in real environments.

---

## Module 6 – Service Account Internals: Token Minting, JWTs, and OAuth2

* **Learning objectives:** Trace exactly how a service account obtains a usable credential under each of the three major mechanisms (attached identity via metadata server, self-signed JWT via a private key, impersonation via IAM Credentials API); distinguish OAuth2 access tokens from OIDC identity tokens and know when each is required; understand Application Default Credentials (ADC) resolution order.
* **Prerequisites:** Module 5.

This is the module where the concept of "service accounts" stops being an IAM abstraction and becomes concrete network calls and cryptography. There are 3 fundamentally different ways a piece of code ends up holding a usable Google credential as a service account. Conflating them is the source of most confusion about "keyless" claims.

### 6.1 Two kinds of tokens you'll mint, and why both exist

- **OAuth2 access token** – a bearer token (opaque string, typically prefixed `ya29.`) used to call Google APIs. It carries **scopes** (legacy, broad, e.g. `https://www.googleapis.com/auth/cloud-platform`) and is authorized against IAM based on the SA's role bindings, not the scope string alone in modern Cloud-Platform-scoped usage – scopes are an outer envelope, IAM permissions are the actual gate. Default lifetime is **1 hour**; can be extended up to **12 hours** for SAs explicitly added to an org policy allow-list for extended lifetime tokens.
- **OIDC identity token (ID token)** – a signed JWT (not opaque) asserting *who the caller is* to a relying party, carrying an `aud` (audience) claim identifying the specific service it's meant for (e.g., a specific Cloud Run service URL). Used when **authenticating to another service** rather than calling a Google API that expects OAuth2 – the canonical example is service-to-service calls on Cloud Run/Cloud Functions, where the receiving service validates the caller's identity by checking the ID token's signature and audience, not by checking OAuth scopes.

**Rule of thumb:**
* Calling a Google Cloud API → OAuth2 access token.
* Authenticating to a custom HTTP service (including another of your own Cloud Run services) → ID token.

### 6.2 Mechanism 1: Attached identity via the metadata server (the common "keyless" path)

When a service account is *attached* to a compute resource (GCE VM, GKE node/pod via Workload Identity, Cloud Run service, Cloud Function, Cloud Build job, App Engine), the runtime environment exposes a **metadata server** reachable only from inside that environment at the link-local address `http://169.254.169.254` (alias `metadata.google.internal`). The application HTTP-calls:

```
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google
```

and receives back a JSON payload containing a short-lived OAuth2 access token. **No private key ever exists on the machine, in any file, in any environment variable.** Internally, Google's infrastructure brokers this: the metadata server is itself authenticated to a backend identity-issuance system as "I am instance/pod X, which is configured to run as SA Y," and that backend mints a token signed with **Google-held private keys that you never see and cannot export**, scoped to the SA's actual permissions. This is why attached-identity usage is described as fully "keyless" – the asymmetric key material backing the cryptographic trust never leaves Google's control plane at all.

For ID tokens (for service-to-service auth), the equivalent call is:

```
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://my-other-service-xyz.a.run.app
```

### 6.3 Mechanism 2: Self-signed JWT via a downloaded private key (the legacy, riskier path)

This is what actually happens when you create a **JSON key** for a service account and use it (e.g., via `GOOGLE_APPLICATION_CREDENTIALS` pointing at the key file). The JSON key contains an RSA private key that **only ever existed locally at creation time** – Google retains the corresponding **public** key (to verify signatures later) but never retains the private key, which is the entire reason key loss is unrecoverable (you cannot "look up" a lost key; you can only revoke it and issue a new one).

The exact OAuth2 flow used is **JWT Bearer Token Flow for Server-to-Server applications** (RFC 7523), executed client-side by the Google auth library:

1. The client library constructs a JWT **claim set**:
   ```json
   {
     "iss": "ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com",
     "sub": "ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com",
     "scope": "https://www.googleapis.com/auth/cloud-platform",
     "aud": "https://oauth2.googleapis.com/token",
     "iat": 1750000000,
     "exp": 1750003600
   }
   ```
   (`exp - iat` is capped at 3600 seconds by Google's token endpoint regardless of what's requested.)
2. The client library builds a JWT header `{"alg":"RS256","typ":"JWT","kid":"<key_id_from_the_json_file>"}` and **signs the header+claims locally** using the private key from the JSON file, producing `signed_jwt`.
3. The client POSTs to Google's token endpoint:
   ```
   POST https://oauth2.googleapis.com/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<signed_jwt>
   ```
4. Google looks up the **public key** corresponding to `kid`, verifies the signature, checks `iss`/`exp`/`aud`, and – only if valid – **mints and returns an OAuth2 access token** (the same kind of token as Mechanism 1 produces, just reached via a different proof of identity).

The private key is the entire trust anchor here: anyone holding the JSON file can perform step 2 indefinitely (until the key is revoked), from anywhere on the internet, with no Google-side control over *where* it's used from. This is precisely why this mechanism, while fully functional and historically the default integration pattern, is now the one Google and most security teams actively try to eliminate (Module 7).

A related but distinct primitive: `signBlob`/`signJwt` calls (via the IAM Credentials API, `iamcredentials.googleapis.com`) let a caller who holds `roles/iam.serviceAccountTokenCreator` ask Google to sign an arbitrary blob/JWT *as* the SA **without ever touching a private key file at all** – Google performs the RS256 signing operation backend-side using key material it manages. This is the bridge into impersonation (Module 8): the same cryptographic *outcome* as Mechanism 2, with none of the static-secret risk.

### 6.4 Mechanism 3: Impersonation via the IAM Service Account Credentials API

Covered in full in Module 8; introduced here for completeness of the token-minting picture. A caller who already holds *some* Google credential (their own user OAuth token, another SA's token, or a federated token from Workload Identity Federation) and has been granted `roles/iam.serviceAccountTokenCreator` on a target SA can call:

```
POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA_EMAIL:generateAccessToken
```

and receive back a short-lived OAuth2 access token **for the target SA**, having authenticated the *request itself* as their own identity. No key, no JWT-signing locally – the caller's own credential is the proof, and IAM's policy on the target SA is the authorization gate.

### 6.5 Application Default Credentials (ADC) – resolution order

ADC is the *search strategy* Google's client libraries use to find a credential automatically, in this fixed order:

1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable, if set, pointing to a JSON key file or, increasingly, an **external account credential configuration file** (the file format used for Workload Identity Federation – Module 10 – which contains no secret at all, only instructions for how to fetch and exchange a token).
2. The well-known file written by `gcloud auth application-default login` (`~/.config/gcloud/application_default_credentials.json`) – intended for local development only, **never** for production workloads.
3. The attached-identity metadata server, if running inside GCE/GKE/Cloud Run/Cloud Functions/Cloud Build (Mechanism 1).
4. Otherwise, failure – `DefaultCredentialsError`.

Production guidance distilled: **the correct ADC outcome in a properly designed system is step 1 pointing at a Workload-Identity-Federation config file (for external workloads) or step 3 (for GCP-native compute) – step 1 pointing at a JSON key should be treated as a deliberate, justified, logged exception, not the default.**

```bash
# Inspect what gcloud/ADC currently resolves to
gcloud auth application-default print-access-token
gcloud auth list

# Use impersonation locally instead of a downloaded key (Module 8 detail)
gcloud auth application-default login --impersonate-service-account=ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com
```

---

## Module 7 – Keys vs. Keyless Auth: Risk Engineering

* **Learning objectives:** Enumerate concrete failure modes of JSON keys; apply organization policy constraints to eliminate or constrain key usage; design a rotation/expiry strategy where keys are unavoidable; recognize key-related findings in audit data.
* **Prerequisites:** Module 6.

### 7.1 Why JSON keys are categorically riskier

A service account JSON key is a **long-lived, unscoped-by-location bearer credential**. Compare its risk profile to the keyless mechanisms from Module 6:

| Property | JSON key | Attached identity | Impersonation / WIF |
|---|---|---|---|
| Lifetime | Indefinite until manually revoked | Minutes–hours, auto-rotated by Google | Minutes–hours, requested per-use |
| Where it can be used from | **Anywhere on the internet** that can reach Google's token endpoint | Only from inside the specific attached environment | Anywhere the *caller's own* credential is valid, but each use is individually authorized and logged |
| What happens if exfiltrated | Full standing access until someone notices and revokes it | Nothing exfiltratable – there's no static secret to steal | The caller's underlying credential would need to be stolen too, and that access is itself narrower/shorter-lived and separately auditable |
| Audit visibility of "who actually used it" | Only "this SA acted" – if multiple humans/systems share the key, individual attribution is lost | Same SA-level attribution, but provenance is the environment itself | **Best attribution**: logs show the calling identity *and* the impersonation chain (Module 8/11) |
| Rotation operational cost | Manual or scripted; routinely neglected in practice | None – fully automatic | None – nothing to rotate, tokens are ephemeral by construction |

Google's own published guidance (best-practices documentation for managing service account keys) is direct about the threat categories: **credential leakage** (keys ending up in git repos, logs, CI artifacts, laptops, support tickets), **privilege escalation** (an attacker who already has a small foothold uses a poorly-secured key to jump to a more privileged identity), **information disclosure** (the key file's metadata/project context revealing infrastructure details), and **non-repudiation failure** (actions taken under a shared key cannot be tied to an individual actor, which both weakens incident response and can be exploited by an insider to "hide" malicious activity behind a workload identity).

### 7.2 Eliminating keys at the organization level

```bash
# Prevent creation of new user-managed keys org-wide
gcloud resource-manager org-policies enable-enforce \
  constraints/iam.disableServiceAccountKeyCreation \
  --organization=123456789012

# Prevent *uploading* externally-generated public key material for an SA
gcloud resource-manager org-policies enable-enforce \
  constraints/iam.disableServiceAccountKeyUpload \
  --organization=123456789012

# Allow exceptions only for specific projects/folders via a more targeted policy
# (org policies support inheritance and per-node overrides, mirroring the resource hierarchy)
```

These constraints, applied at the Organization node, propagate down to every folder and project unless explicitly overridden at a lower node (org policy inheritance follows the same hierarchy as IAM, but with its own override semantics – a child node can relax or further restrict, depending on the constraint's configured inheritance behavior). New Google Cloud organizations increasingly ship with key-creation restrictions enabled by default, reflecting Google's own stated direction of phasing static keys out as the default integration pattern.

### 7.3 If you cannot eliminate keys (legitimate residual cases)

Some integration patterns – typically third-party SaaS products that only support static-key auth and have no support for impersonation or WIF – still require a JSON key. When this is genuinely unavoidable:

- **Scope the SA's role bindings to the absolute minimum** the third party needs, on the narrowest resource possible (a single bucket, a single dataset) – never project-level `editor`/`owner`.
- **Set an organization policy enforcing maximum key age** so any key, once issued, becomes unusable after a bounded period even if nobody manually rotates it – this is a critical defense-in-depth control because manual rotation discipline reliably degrades over time across an organization.
- **Store the key only in a secrets manager** (Module 12) with access logging, never in source control, CI YAML, container images, or shared drives – and treat "key checked into git" as a sev-1 incident requiring immediate revocation, not a cleanup task.
- **Alert on key usage from unexpected IP ranges/ASNs** via Cloud Audit Logs (Module 11) – a key that's supposed to be used only from one SaaS vendor's documented egress ranges showing activity elsewhere is a strong compromise signal.
- **Treat every key as eventually compromised** in your threat model – the question is not "could this leak" but "when it leaks, what's the blast radius, and how fast do we detect it."

### 7.4 Rotation in practice

```bash
# Create a new key, deploy it, *then* delete the old one (avoid downtime)
gcloud iam service-accounts keys create new-key.json \
  --iam-account=ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com

# ... deploy new-key.json to the consuming system, verify it's working ...

gcloud iam service-accounts keys list \
  --iam-account=ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com

gcloud iam service-accounts keys delete OLD_KEY_ID \
  --iam-account=ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com
```

A service account supports a limited number of concurrently active user-managed keys (low double digits) – this ceiling is itself a deliberate forcing function discouraging the "create dozens of keys, never clean any up" pattern.

### 7.5 The "Asset Key Thief" case study (a real, disclosed Google Cloud vulnerability)

In 2023, security researchers publicly [disclosed](https://engineering.sada.com/asset-key-thief-disclosure-cfae4f1778b6) a privilege-escalation technique, since remediated by Google, in which a principal holding only the **Cloud Asset Viewer** role (or any role containing the underlying `cloudasset.assets.searchAllResources` permission) at a project, folder, or organization scope could, under specific conditions, retrieve the **private key material of user-managed service account keys** through the Cloud Asset Inventory API's resource-search responses.

The affected keys were specifically those created via `CreateServiceAccountKey` where Google generated the private key material on the customer's behalf – not keys where the customer uploaded their own public key. Crucially, the retrieval window was bounded: only keys created or rotated within the prior 12–24 hours were accessible through the vulnerable code path.
 What looked like a harmless read-only inventory/auditing permission became a path to fully impersonating other service accounts.
 
 The case is instructive for two reasons beyond the specific (now-patched) bug:
 
 First, it demonstrates that **"read-only" and "low-risk" are not synonyms** – a permission that exposes structured metadata about your environment can expose far more than its name implies, depending on exactly what fields a service returns.
 
 Second, organizations practicing **frequent key rotation** were, counter-intuitively, more exposed during the vulnerability window, because more recently-created key material was retrievable through the affected code path – a reminder that mitigations (rotation) designed for one threat model (long-lived key compromise) don't automatically help against every threat model, and reinforces why **eliminating keys entirely**, rather than rotating them faster, is the durable fix.

---

## Module 8 – Impersonation Internals & Delegation Chains

* **Learning objectives:** Explain exactly what happens, end-to-end, when one identity impersonates another; distinguish `serviceAccountUser` (actAs/attach) from `serviceAccountTokenCreator` (mint-as) with concrete examples of each; configure and reason about multi-hop delegation chains; use impersonation safely in local development and automation.
* **Prerequisites:** Modules 5–6.

### 8.1 What "impersonation" means technically

Impersonation is **not** "logging in as" another identity in the sense of obtaining its long-term secret. It is: *a request, authenticated as caller C, asking Google's IAM Credentials API to mint a short-lived credential that represents target identity T, where Google itself checks that C is authorized to make this request before minting anything.* The target SA's "private key" (in the keyless-by-design sense from Module 6) never enters the picture; the entire operation is mediated by IAM policy on the target SA plus a backend signing/minting operation Google performs on C's behalf.

The permission that gates this is `iam.serviceAccounts.getAccessToken`, bundled into the predefined role **`roles/iam.serviceAccountTokenCreator`**, granted **on the target service account as a resource** (not on the project) to the caller (which may itself be a user, a group, or another service account – impersonation chains can and do start from any of these).

### 8.2 The four IAM Credentials API operations

```
POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:generateAccessToken
POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:generateIdToken
POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:signBlob
POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:signJwt
```

- **`generateAccessToken`** – mint an OAuth2 access token as the target SA, scoped to requested OAuth scopes, default 1-hour lifetime (extendable to 12 hours for allow-listed SAs, same mechanism as Module 6.1).
- **`generateIdToken`** – mint an OIDC ID token as the target SA for a specified `audience`, for service-to-service authentication.
- **`signBlob` / `signJwt`** – ask Google to RS256-sign an arbitrary byte blob or JWT claim set, as the target SA, without exposing key material – used by some legacy integrations and certain Google services (e.g., signed URLs for Cloud Storage) that need a cryptographic signature attributable to the SA's identity.

### 8.3 `serviceAccountUser` vs. `serviceAccountTokenCreator` – the distinction that matters most

These two roles are **frequently confused** and **independently exploitable**, so treat them as entirely separate capabilities:

- **`roles/iam.serviceAccountUser`** grants `iam.serviceAccounts.actAs`. This lets the holder **attach** the target SA to a *new resource they are creating* – e.g., launching a Compute Engine VM, deploying a Cloud Function, or submitting a Cloud Build job, specifying "run this as SA X." The holder does not get a token for SA X directly through this permission; instead, they get to **cause a Google-managed resource to run as SA X**, and that resource then independently obtains tokens via the attached-identity metadata server (Mechanism 1, Module 6.2). The risk: if SA X is privileged, anyone with `actAs` on X plus *any* permission to create a compute resource (even a narrowly-scoped one) can effectively run arbitrary code as X.
- **`roles/iam.serviceAccountTokenCreator`** grants `iam.serviceAccounts.getAccessToken` (and the sibling sign/ID-token permissions). This lets the holder **directly mint a credential as SA X right now**, with no need to create any other resource at all – the most direct path to "become" SA X for API-calling purposes.

A useful operational rule: **`serviceAccountUser` answers "can you launch things as this SA," `serviceAccountTokenCreator` answers "can you directly become this SA."** Grant each independently and only to the narrowest set of principals that genuinely need that specific capability – a CI/CD deployer typically needs `serviceAccountUser` on the runtime SA it deploys workloads with, while a human doing live debugging-as-the-SA needs `serviceAccountTokenCreator`, and these are very rarely the same audience.

### 8.4 Delegation chains

`generateAccessToken` supports a `delegates` field allowing **chained impersonation**: caller C impersonates SA B, which in turn impersonates target SA A, where C itself only needs `serviceAccountTokenCreator` on B, and B needs `serviceAccountTokenCreator` on A – C does **not** need any direct grant on A at all. This is the mechanism behind common patterns like "a central automation SA in a security project is allowed to impersonate per-team SAs, which are in turn the only principals allowed to impersonate the most sensitive production SA" – each hop is independently auditable and independently revocable by removing one binding, without needing to touch the others.

```bash
# CLI: impersonate directly (single hop)
gcloud compute instances list \
  --project=my-project-id \
  --impersonate-service-account=readonly-sa@my-project-id.iam.gserviceaccount.com

# CLI: chained impersonation (C -> B -> A), expressed as a comma-separated delegate chain
gcloud compute instances list \
  --project=my-project-id \
  --impersonate-service-account=target-sa-A@proj.iam.gserviceaccount.com \
  --delegate-chain=delegate-sa-B@proj.iam.gserviceaccount.com
```

Chain length is bounded (a small fixed maximum hop count enforced by the API) precisely to keep audit trails easy to reason about, and to prevent unbounded indirection from being used to obscure provenance.

### 8.5 Local development without ever touching a key

```bash
# One-time: grant your human user identity the right to impersonate the target SA
gcloud iam service-accounts add-iam-policy-binding \
  ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com \
  --member="user:you@example.com" \
  --role="roles/iam.serviceAccountTokenCreator"

# Day-to-day: ADC now resolves through impersonation, no JSON key file anywhere
gcloud auth application-default login \
  --impersonate-service-account=ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com

# Equivalent for one-off CLI commands without changing ADC globally
gcloud storage ls gs://my-bucket --impersonate-service-account=ingest-pipeline-sa@my-project-id.iam.gserviceaccount.com
```

This is the recommended replacement for "download a key so I can test locally" in essentially every case – the human's own authentication (likely already MFA-protected) is the proof, every impersonation call is individually logged with the human's identity *and* the target SA visible (Module 11), and there is no file to forget to delete from a laptop.

### 8.6 Common pitfalls

- **Granting `serviceAccountUser` at the project level** (`roles/iam.serviceAccountUser` bound on the *project* resource) instead of on the specific target SA – this grants `actAs` over **every current and future SA in the project**, not just the one intended. Always bind these roles on the SA resource itself unless you have a deliberate, documented reason to grant it broadly.
- **Forgetting that `serviceAccountTokenCreator` granted to a group silently extends to every current and future group member** – group membership changes are often managed outside the cloud team's direct visibility (HR systems, self-service group tools), making this an easy place for scope to creep without anyone touching IAM directly.
- **Using impersonation chains as a substitute for actually reducing standing privilege**, rather than as a tool for reducing standing privilege – chaining through five SAs to eventually reach one with `roles/owner` does not make that `owner` grant safer, it just adds hops.

---

## Module 9 – Cross-Project & Cross-Org Access Patterns

* **Learning objectives:** Design and implement service-account-based access across project boundaries; understand the specific permission combinations needed for common architectures (shared VPC, centralized logging/data lake, cross-org partner access); recognize the security tradeoffs of each pattern.
* **Prerequisites:** Modules 5–8.

### 9.1 The core mechanic: an SA from project A can be granted roles in project B

The principal's "home project" (if it even has one) does not constrain where it can be granted permissions.
So while SAs are created and managed *within a project*, their identities are effectively *global IAM principals*, just like users, and can be granted permissions on resources anywhere in the organization – or even in entirely different organizations if the IAM policy allows it.

Nothing structurally prevents a service account created in Project A from being bound into the `allow` policy of Project B (or a resource within it) – there is no "same project" restriction in role bindings. This is the foundation of essentially all cross-project architecture:

```bash
# SA lives in the "pipeline" project, but is granted access to data in the "warehouse" project
gcloud projects add-iam-policy-binding warehouse-project-id \
  --member="serviceAccount:etl-sa@pipeline-project-id.iam.gserviceaccount.com" \
  --role="roles/bigquery.dataEditor"
```

The security question is never *"can this work"* (it always can) – it's **"who can grant this, who can audit it, and what happens if the source project is compromised."** A common, easy-to-miss exposure: Project A's admins (anyone with `serviceAccountTokenCreator` or `serviceAccountUser` on `etl-sa`) now have an indirect path into Project B's data, **even if they have zero direct IAM grants in Project B at all** – because they can act as the SA that does. Cross-project access reviews must therefore trace **both** ends:
* who can act as the SA?
* what can the SA reach?

### 9.2 Pattern: centralized data lake / warehouse access

Multiple producer projects, one consumer (analytics) project:

- Each producer project's pipeline SA is granted **only** `roles/bigquery.dataEditor`/`roles/storage.objectCreator` on a specific destination dataset/bucket in the central project – never broad project-level roles in the central project.
- The central project's analyst-facing SA/group is granted **only read** roles, and ideally scoped per-dataset using IAM Conditions (resource-name-prefix or tag-based, Module 4) rather than one project-wide read grant, so a compromise of the analytics layer doesn't expose every producer's data uniformly.
- Use **separate SAs per producer pipeline** rather than one shared "ingest-everything" SA – this bounds blast radius and keeps audit logs attributable to a specific pipeline rather than an undifferentiated shared identity.

### 9.3 Pattern: Shared VPC and network-adjacent cross-project grants

Shared VPC architectures (a **"host"** project owning the network, **"service"** projects attaching workloads to it) require specific cross-project roles independent of data-plane IAM – e.g., `roles/compute.networkUser` granted to service-project SAs/groups on the host project, so workloads in service projects can use host-project subnets. This is a useful reminder that **cross-project IAM isn't only a data-access concern** – network attachment, KMS key access (`roles/cloudkms.cryptoKeyEncrypterDecrypter` granted cross-project to a workload's SA so it can use a centrally-managed KMS key), and Secret Manager access (Module 12) all follow the identical cross-project role-binding mechanic.

### 9.4 Pattern: cross-organization (partner/vendor) access

When the external party is in a **different GCP Organization** entirely (a partner company, an acquired entity not yet merged into your org, a vendor), you have 3 realistic options, ordered by preference:

1. **Workload Identity Federation** (Module 10) – the partner's own workload identity (their own cloud's identity, or an OIDC token they control) is federated directly; no SA or credential of yours is ever shared with them. Strongly preferred when the partner's workload can produce a usable OIDC/SAML assertion.
2. **A dedicated SA in your project, with `serviceAccountTokenCreator` granted to a principal the partner controls** (most cleanly, a federated identity as preceding WIF/option-1, or, less ideally, a Google Group containing specific named individuals at the partner if no federation is feasible) – the partner impersonates short-lived credentials rather than ever holding a static key of yours.
3. **A JSON key handed to the partner** – last resort, only when the partner's tooling has no support for either of the above, and should come with the full Module 7.3 mitigations (narrowest possible role, max key age enforced, usage-anomaly alerting) plus a contractual/operational expectation of immediate revocation if the relationship ends.

### 9.5 `gcloud`: auditing who can reach across a boundary

```bash
# Find every principal from outside this project's own domain/SA namespace
# bound anywhere in this project's allow policy
gcloud projects get-iam-policy warehouse-project-id --format=json \
  | jq '.bindings[].members[]' \
  | grep -v "@warehouse-project-id.iam.gserviceaccount.com" \
  | sort -u

# Org-wide: every cross-project SA binding under a folder
gcloud asset search-all-iam-policies \
  --scope=folders/111111111111 \
  --query="policy:serviceAccount"
```

### 9.6 Common pitfalls

- **A producer pipeline SA granted `roles/bigquery.admin` "to be safe"** in the central warehouse project, when `dataEditor` on one dataset would suffice – this single over-grant means *any* compromise of the producer pipeline becomes a compromise of the entire warehouse's schema and IAM, not just its own data.
- **Forgetting that VPC Service Controls perimeters (a separate, complementary control) interact with cross-project SA access** – an SA can hold a perfectly valid IAM role and still be blocked from calling certain APIs if a VPC-SC perimeter doesn't include its calling context; conversely, don't rely on VPC-SC as a substitute for correct IAM scoping – they solve different problems (data exfiltration boundary vs. who-can-do-what) and are meant to be layered.
- **Cross-org partner access granted to a personal/individual partner email** rather than a partner-controlled group or federated identity – when that individual leaves the partner company, nobody on your side is notified, and the grant silently persists.

---

# Part III – Advanced IAM & Security

## Module 10 – Workload Identity & Workload Identity Federation

* **Learning objectives:** Distinguish GKE Workload Identity from external Workload Identity Federation precisely; trace the OAuth 2.0 Token Exchange (RFC 8693) mechanics underlying both; configure a GKE pod-to-GSA binding and a GitHub Actions OIDC binding end-to-end; write correct attribute mappings and attribute conditions.
* **Prerequisites:** Modules 6, 8.

### 10.1 The shared foundation: OAuth 2.0 Token Exchange via the Security Token Service

Both mechanisms in this module rest on the same primitive: Google's **Security Token Service** (`sts.googleapis.com`), implementing the **OAuth 2.0 Token Exchange** standard (RFC 8693). The pattern is always: *present a token from some other trusted issuer → STS validates it against a configured trust relationship → STS returns a short-lived Google federated token representing that external identity*, which can then either be used directly (if granted roles itself) or used to impersonate a Google service account (more common, and recommended, because it lets you express access as a normal SA role binding rather than managing role bindings on raw federated-subject strings).

### 10.2 GKE Workload Identity (cluster-internal)

GKE Workload Identity bridges the gap between **Kubernetes-native** security and **Google Cloud IAM**. It eliminates the need for legacy, high-risk static `JSON` service account keys by letting cluster workloads securely adopt a specific Google Cloud identity.

GKE Workload Identity binds a **Kubernetes Service Account (KSA)** – a Kubernetes-native, namespace-scoped identity object, unrelated to Google IAM by itself – to a **Google Service Account (GSA)**, so that pods running as a given KSA automatically receive GSA credentials with zero key material anywhere in the cluster.

The architectural identity flow works as follows:
```
[ Pod ] ──► [ KSA ] ──► [ Workload Identity Principal ] ──► [ GSA ] ──► [ GCP Resource ]
```
1. The Pod runs under a designated Kubernetes Service Account (**KSA**), which is its identity within the cluster.
2. The KSA has been pre-authorized to impersonate a specific GSA via `roles/iam.workloadIdentityUser` granted *on the GSA* to the KSA's Workload Identity pool subject.
3. At runtime, the GKE Workload Identity agent exchanges the pod's Kubernetes-issued OIDC token for a short-lived Google OAuth2 access token via the Security Token Service (STS, RFC 8693). This exchange happens transparently to application code, which simply calls the standard metadata-server endpoint (Module 6.2).
4. The pod now holds a short-lived credential representing the GSA's identity, with no key material ever existing on disk or in any environment variable.
5. When the pod calls a GCP API, the target resource evaluates the GSA's IAM role bindings (e.g., a `roles/storage.objectViewer` binding scoped to a specific bucket) and grants or denies access accordingly.

**Mechanics:**

1. Each GKE cluster with Workload Identity enabled shares a per-project **workload identity pool** (WIP) automatically, named `PROJECT_ID.svc.id.goog`.
2. Every KSA in the cluster has an implicit identity within that pool, expressed as the subject `serviceaccount:PROJECT_ID.svc.id.goog[NAMESPACE/KSA_NAME]`.
3. You bind the GSA (as a resource) to allow that specific KSA subject to impersonate it, using `roles/iam.workloadIdentityUser`:

```bash
gcloud iam service-accounts add-iam-policy-binding \
  payments-backend-gsa@my-project-id.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:my-project-id.svc.id.goog[payments/payments-ksa]"
```

4. You annotate the KSA, declaring which GSA it's allowed to use:

```bash
kubectl annotate serviceaccount payments-ksa \
  --namespace payments \
  iam.gke.io/gcp-service-account=payments-backend-gsa@my-project-id.iam.gserviceaccount.com
```

```yaml
# equivalent YAML:
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payments-ksa
  namespace: payments
  annotations:
    # Specifies the target GSA identity for token impersonation
    iam.gke.io/gcp-service-account: "payments-backend-gsa@my-project-id.iam.gserviceaccount.com"
```

5. At runtime, a pod using `payments-ksa` calls the metadata-server-equivalent endpoint exposed by the GKE Workload Identity webhook/agent injected into the pod's network namespace. That component holds the pod's Kubernetes-issued, cluster-internal **OIDC token** (the KSA's projected service account token, itself a JWT signed by the cluster's own OIDC issuer), and exchanges it via STS for a Google access token scoped to the bound GSA – this exchange is exactly RFC 8693 token exchange, with the Kubernetes JWT as the "subject token" and the GSA's federated representation as the result. The application code calls the standard metadata-server URL (Module 6.2) and is unaware any exchange happened – this is intentional, so existing Google client libraries work unmodified.

The net effect: **one GKE cluster can run many microservices, each with its own least-privilege GSA, none of them holding or ever seeing a key**, simply by giving each microservice's pods a distinct KSA mapped to a distinct GSA.

>Note that WIP is scoped to the **GCP Project** (not a single GKE cluster), so any GKE clusters you create within the *same* project will share the *same* WIP.

This means that if you have 2 different GKE clusters in the same project – `cluster-a` and  `cluster-b` – and both clusters have a namespace named `backend` with a KSA named `back-ksa`, they will be treated as the exact same identity by Google Cloud IAM.

This is not a bug or security oversight, but a feature called "[Identity Sameness](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity#identity_sameness)". Identity Sameness allows the same Workload Identities to be reused across multi-cluster deployments of the same workloads (in trusted/single-tenant clusters) – e.g. multi-region clusters. In the below diagram, `back-ksa` and its corresponding Workload-Identity-pool principal are reused/shared by both clusters. The database-enabled GSA which allows its impersonation by the linked WI-principal should be reused/shared as well.
![Workload Identity Sameness](https://docs.cloud.google.com/static/kubernetes-engine/images/identity-sameness-workload-identity.svg)

If you need to isolate permissions between clusters with distinct lifecycles and trust levels (e.g. `dev` and `prod`), you have options:
* Use different GCP projects for each GKE cluster (safest)
* Use distinct namespace names (e.g. `dev-namespace` vs `prod-namespace`)
* Use distinct KSA names (e.g. `dev-app-ksa` vs `prod-app-ksa`)
* Use IAM Conditions to restrict access based on attributes like the cluster name

### 10.3 External Workload Identity Federation (non-GKE: AWS, Azure, on-prem, CI/CD)

The general-purpose product for federating **any** OIDC- or SAML-capable external identity provider, configured with 2 objects:

- A **Workload Identity Pool** – a container for external identities, scoped to a project.
- One or more **Providers** inside the pool – each one trusts a specific external issuer (e.g., `https://token.actions.githubusercontent.com` for GitHub Actions, AWS's STS-based provider type for AWS workloads, Azure AD's issuer for Azure workloads), with an **attribute mapping** (how claims in the external token map to Google-understood attributes like `google.subject`) and an optional **attribute condition** (a CEL expression restricting which external tokens are accepted at all – this is the critical security control, see 10.4).

End-to-end example: GitHub Actions deploying to Cloud Run with zero stored secrets.

```bash
# 1. Create the pool
gcloud iam workload-identity-pools create "github-pool" \
  --project="my-project-id" --location="global" \
  --display-name="GitHub Actions Pool"

# 2. Create the OIDC provider inside the pool, trusting GitHub's issuer,
#    with an attribute condition restricting to one specific repo
gcloud iam workload-identity-pools providers create-oidc "github-provider" \
  --project="my-project-id" --location="global" \
  --workload-identity-pool="github-pool" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='my-org/my-repo'"

# 3. Allow the federated identity (scoped to that repo) to impersonate a deploy GSA –
#    note this grants the *pool/provider subject*, not a key, the right to impersonate
gcloud iam service-accounts add-iam-policy-binding \
  ci-deployer-gsa@my-project-id.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/attribute.repository/my-org/my-repo"
```

```yaml
# .github/workflows/deploy.yml (relevant excerpt)
permissions:
  id-token: write     # required: lets GitHub mint the OIDC token for this job
  contents: read
jobs:
  deploy:
    steps:
      - uses: google-github-actions/auth@v3
        with:
          workload_identity_provider: "projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/providers/github-provider"
          service_account: "ci-deployer-gsa@my-project-id.iam.gserviceaccount.com"
      - uses: google-github-actions/deploy-cloudrun@v3
        with:
          service: my-service
          region: us-central1
```

At runtime: GitHub's Actions runner mints a short-lived OIDC token signed by GitHub, carrying claims like `repository`, `repository_owner`, `ref`, and a composite `sub` (e.g. `repo:my-org/my-repo:ref:refs/heads/main`). The `auth` action presents this token to STS, which validates it against the provider's issuer/attribute condition, returns a federated Google token, and then – because a `service_account` was specified – that federated token is immediately used to call `generateAccessToken` (Module 8) and impersonate the deploy GSA. **No JSON key exists anywhere in this pipeline, in a GitHub secret or otherwise**, and the blast radius of a leaked CI token is bounded to one hour and to whatever the specific deploy GSA can do.

### 10.4 The attribute condition is the actual security boundary – get it precisely right

The single highest-leverage mistake in WIF configuration is an **attribute condition that is too permissive** – e.g., omitting it entirely, or writing `assertion.repository_owner=='my-org'` (which trusts *every repo in the org*, including forks if not carefully scoped, and any future repo anyone creates there) when you meant one specific repo and one specific branch/environment. A well-scoped condition for a production-deploy provider looks like:

```
assertion.repository=='my-org/my-repo' && assertion.ref=='refs/heads/main'
```

Treat the attribute condition with the same rigor as a deny-policy rule (Module 4) – it is, functionally, the only thing standing between "any GitHub Actions workflow anywhere" and "this one specific repo's main-branch deploy job."

### 10.5 GKE Workload Identity vs. external WIF – when to use which

| | GKE Workload Identity | External WIF |
|---|---|---|
| Identity source | Kubernetes Service Account, internal to one GKE cluster | Any external OIDC/SAML IdP (GitHub, GitLab, AWS, Azure, on-prem) |
| Setup unit | Pool auto-created per project (`PROJECT_ID.svc.id.goog`), not per cluster | Pool + Provider you create explicitly, can serve many external systems |
| Typical use | Microservices running inside GKE calling GCP APIs | CI/CD runners, workloads on other clouds, on-prem systems, partner integrations |
| Underlying mechanism | Same STS/RFC 8693 token exchange | Same STS/RFC 8693 token exchange |

They are the same underlying machinery aimed at two different identity-source shapes – recognizing this prevents treating them as unrelated topics to memorize separately.

---

## Module 11 – Audit Logging, Detection & Privilege Escalation Paths

* **Learning objectives:** Differentiate Admin Activity vs. Data Access audit logs and their retention/default-on behavior; build queries to detect impersonation, key creation, and IAM policy changes; enumerate the canonical service-account privilege-escalation chains and the specific permission combination behind each; use Policy Analyzer/IAM Recommender to find and remediate over-grants before they're exploited.
* **Prerequisites:** Modules 5–10.

### 11.1 Cloud Audit Logs – the 2 log streams that matter

- **Admin Activity audit logs** – every API call that **modifies configuration or metadata**, including every `setIamPolicy` call, every `CreateServiceAccount`/`DeleteServiceAccount`, every `CreateServiceAccountKey`/`DeleteServiceAccountKey`. **Always enabled, cannot be disabled, and retained for 400 days** – this is a hard platform guarantee, not a configurable setting, which makes it the bedrock of any IAM forensic timeline.
- **Data Access audit logs** – calls that **read configuration/metadata or read/write user data**, including, critically, calls to `iamcredentials.googleapis.com` (`GenerateAccessToken`, `GenerateIdToken`, `SignBlob`, `SignJwt`) – i.e., **every impersonation event**. Unlike Admin Activity, Data Access logs for many services are **not on by default** and must be explicitly enabled (and can carry meaningful log volume/cost at scale) – meaning a very common and consequential gap in real environments is: *IAM policy changes are always logged, but actual use of impersonation may not be, unless Data Access logging was deliberately turned on.* Confirming this is enabled for `iamcredentials.googleapis.com` (and ideally for the resource types you most care about – Cloud Storage, BigQuery) should be a day-1 checklist item, not an afterthought discovered during an incident.

```bash
# Enable Data Access audit logs at the org level (illustrative; exact mechanism is via
# the Cloud Logging / Access Transparency configuration surfaces, not a single gcloud flag
# for every service – verify current configuration UI/Terraform resource for your services)
gcloud logging settings update --organization=123456789012 \
  --data-access-logging=true   # representative; consult current docs per-service
```

### 11.2 Log-search Queries to have ready before an incident, not during one

```bash
# Every impersonation (token-minting) event in the last 24h
resource.type="audited_resource"
protoPayload.serviceName="iamcredentials.googleapis.com"
protoPayload.methodName="GenerateAccessToken"
timestamp>="2026-06-15T00:00:00Z"

# Every service account key created or deleted org-wide
protoPayload.serviceName="iam.googleapis.com"
(protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey" OR
 protoPayload.methodName="google.iam.admin.v1.DeleteServiceAccountKey")

# Every IAM policy mutation – the highest-signal query for "who changed access"
protoPayload.methodName="SetIamPolicy"

# Impersonation chains: who is the *original* caller behind a service-acting-as-service event
# (look at protoPayload.authenticationInfo.serviceAccountDelegationInfo –
#  populated specifically for delegated/impersonated calls)
protoPayload.authenticationInfo.serviceAccountDelegationInfo:*
```

The `serviceAccountDelegationInfo` field deserves special attention: for any API call made via impersonation (single-hop or chained), this field in the audit log entry lists every identity in the delegation chain, with **the principal at the bottom of the list being the original human/system that initiated the chain** – this is what makes impersonation auditable end-to-end even through multiple hops, and is precisely the field Security Command Center's *"Anomalous Service Account Impersonator"* detector inspects.

### 11.3 Security Command Center detections relevant to service accounts

Google's managed threat-detection layer (Event Threat Detection/Security Command Center) ships specific findings tuned to this exact threat surface, including **"Privilege Escalation: Anomalous Service Account Impersonator"** (flags impersonation activity inconsistent with a service account's historical usage pattern – e.g., a delegation chain or calling identity never seen before, or access to data the SA doesn't normally touch) and detectors for anomalous IAM grant patterns and unexpected service-account key creation. The standard response runbook for such a finding: identify every principal in the delegation chain, confirm with the SA's actual owner whether the action was legitimate, and – if not – disable (don't necessarily immediately delete) the SA, rotate/delete any of its keys, and review what the SA touched during the suspect window before deciding on further containment.

### 11.4 The canonical privilege-escalation chains (know these cold)

These are well-documented, repeatedly-rediscovered patterns (the most cited original write-up is Rhino Security Labs' 2020 research into GCP IAM privilege escalation) – the unifying theme is **a principal holding a "deploy" or "manage compute resource" permission, combined with `actAs`/`serviceAccountUser` on a more privileged SA, lets them run arbitrary code as that more-privileged SA.**

1. **`iam.serviceAccountKeyAdmin` on a privileged SA** → create a new key for that SA → authenticate as it directly. The most direct chain: the permission to manage keys *is* the permission to mint yourself a durable credential for that identity.
2. **`iam.serviceAccountTokenCreator` on a privileged SA** → call `generateAccessToken` → hold a live credential as that SA, no key required, often harder to spot because no key-creation event fires.
3. **`compute.instanceAdmin*` + `iam.serviceAccountUser` on a privileged SA** → create a new VM (or edit an existing one's metadata/startup script, depending on exact permission set) attached to that SA → SSH/serial-console in, or rely on the startup script, and pull a token from the metadata server (Module 6.2) as that SA.
4. **`cloudfunctions.developer`/`cloudfunctions.admin` + `iam.serviceAccountUser` on a privileged SA** → deploy a function configured to run as that SA, with attacker-controlled code → the function mints tokens as that SA on invocation.
5. **`cloudbuild.builds.editor`/Deployment-pipeline permissions + `iam.serviceAccountUser` on Cloud Build's (often broadly-privileged-by-default) runtime SA** → submit a build step that simply calls `gcloud` or curls the metadata server → tokens as the Cloud Build SA, which in many legacy-configured projects is far more powerful than the submitter's own direct permissions.
6. **`iam.roles.update` (custom role editing) on a role currently bound to a privileged scope** → quietly add permissions to a custom role you can already touch, which immediately grants those permissions to **everyone already bound to that role**, including the attacker, without ever creating a new binding (a stealthier variant, because the binding list itself never changes – only an audit of `SetIamPolicy` is insufficient here; you also need to watch `google.iam.admin.v1.CreateRole`/`UpdateRole` events).

The remediation principle behind all these privilege-escalation threats: **never co-locate *"permission to attach/mint-as a SA"* with *"permission to manage that SA's own privilege level"* in a single principal**, and treat any combination of *"can manage compute/serverless deploy surface"* + *"can act as a privileged SA"* as equivalent in risk to granting that privilege level directly – because, functionally, it is.

### 11.5 Finding these before an attacker does: Policy Analyzer and IAM Recommender

```bash
# IAM Recommender: roles that have granted permissions far beyond actual usage,
# i.e., concrete least-privilege downsizing suggestions based on observed activity
gcloud recommender recommendations list \
  --project=my-project-id \
  --location=global \
  --recommender=google.iam.policy.Recommender

# Policy Analyzer (via Cloud Asset Inventory): find every principal that can reach
# a specific sensitive permission anywhere in scope – the proactive version of
# "could someone privilege-escalate via this chain right now"
gcloud asset analyze-iam-policy \
  --organization=123456789012 \
  --full-resource-name="//cloudresourcemanager.googleapis.com/projects/PROD-PROJECT" \
  --permissions="iam.serviceAccounts.getAccessToken,iam.serviceAccounts.actAs"
```

Run the second query, specifically for the permission pairs in 11.4, against every production-tier project on a recurring schedule (monthly at minimum, ideally as a CI check against your Terraform IAM definitions) – this turns *"we hope nobody can escalate"* into an auditable, continuously verified claim.

---

## Module 12 – Secret Management vs. Service Accounts

* **Learning objectives:** Draw a precise boundary between "identity" (service accounts, IAM) and "secrets" (Secret Manager, KMS-wrapped application secrets); avoid the common anti-pattern of using SA keys as a general-purpose secrets-distribution mechanism; design correct access patterns for application secrets that themselves need to be fetched by a workload identity.
* **Prerequisites:** Modules 5–10.

### 12.1 The category error to avoid

Service accounts answer ***"who is this workload"***; Secret Manager answers ***"how does this workload safely obtain a piece of sensitive configuration it needs"*** (a database password, a 3rd-party API key, a TLS private key, an HMAC signing secret). These are different problems, and a common architectural mistake is using service-account JSON keys as a stand-in general-purpose secret-distribution mechanism – e.g., *"we'll just bake the SA key into the container image alongside the database password,"* conflating identity material with arbitrary application secrets and inheriting the worst properties of both (Module 7's static-key risks, plus lack of fine-grained per-secret access control or rotation tooling).

The correct layering:<br>
**A workload authenticates as itself using a keyless mechanism** (Modules 6/10) **→ that identity (the SA) is granted IAM access to specific secrets in Secret Manager → the workload fetches the secret it actually needs at runtime using its own already-established identity.** The SA never needs a key; Secret Manager never needs to know anything about how the SA authenticated.

```bash
# Grant the workload's SA access to exactly one secret, not all secrets in the project
gcloud secrets add-iam-policy-binding payments-db-password \
  --member="serviceAccount:payments-backend-gsa@my-project-id.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Application code: fetch using ADC, which resolves via attached identity or WIF –
# no separate "secret to authenticate to Secret Manager" is ever needed
gcloud secrets versions access latest --secret="payments-db-password"
```

### 12.2 What Secret Manager is good at that IAM/SAs are not, and vice versa

| Need | Right tool |
|---|---|
| "Is this workload who it claims to be" | IAM + Service Account (Modules 5–10) |
| "What can this verified identity access" | IAM Role Bindings + conditions |
| "Store and version a database password, rotate it, audit who fetched it" | Secret Manager |
| "Encrypt application-level data at rest with envelope encryption" | Cloud KMS, accessed via an IAM-authorized SA |
| "Give a 3rd-party SaaS a credential because it can't do federation" | A narrowly-scoped SA key (Module 7.3), itself ideally stored *in* Secret Manager rather than a flat file, with access to that one secret restricted to the few principals/automation that need to retrieve it for deployment |

### 12.3 Pitfall: secrets *about* service accounts, stored insecurely

Beyond keys, watch for SA-*adjacent* secrets handled carelessly: OAuth client secrets for SA-based OAuth flows in some legacy integrations, webhook signing secrets tied to a service identity, or impersonation target lists hardcoded in application config where they'd be better expressed as IAM bindings reviewable through the standard audit tooling from Module 11. The following general principle applies here: **anything that is itself a bearer secret belongs in Secret Manager (or KMS-wrapped storage) with its own access policy and rotation story – it should never piggyback on a service account's identity material as its distribution channel.**

---

## Module 13 – Production Architecture Patterns & Real-World Breaches

* **Learning objectives:** Apply everything from Modules 1–12 to the complete reference architectures discussed below; study documented real-world incidents involving service-account/IAM misconfiguration and extract the specific control that would have prevented or contained each one.
* **Prerequisites:** All prior modules.

### 13.1 Reference architecture: microservices on GKE

A typical multi-team GKE platform, applying every principle from this course:

```
GKE Cluster (Workload Identity enabled)
 ├── namespace: payments
 │     KSA: payments-ksa  --workloadIdentityUser ─▶  GSA: payments-gsa
 │                                                     roles: bigquery.dataEditor (dataset: payments_prod, via condition)
 │                                                            cloudkms.cryptoKeyEncrypterDecrypter (key: payments-pii-key)
 ├── namespace: notifications
 │     KSA: notify-ksa  --workloadIdentityUser ─▶  GSA: notify-gsa
 │                                                     roles: secretmanager.secretAccessor (secret: sendgrid-api-key only)
 │                                                            pubsub.publisher (topic: notify-events only)
 └── namespace: ci
       KSA: deployer-ksa  --workloadIdentityUser ─▶  GSA: deployer-gsa
                                                       roles: container.developer (this cluster only)
                                                              iam.serviceAccountUser on payments-gsa/notify-gsa ONLY
                                                              (so it can deploy workloads attached to them, but cannot
                                                               directly mint tokens as them – no tokenCreator grant)
```

Design decisions worth calling out explicitly:
*  **1 GSA per service**, never a shared "gke-workloads-gsa" – this bounds blast radius per Module 9's logic.
* **Resource-level conditions on data roles** (`payments-gsa` can touch only the `payments_prod` dataset, expressed via a `resource.name.startsWith(...)` condition per Module 4) rather than project-wide `bigquery.dataEditor`.
* **The CI deployer GSA gets `serviceAccountUser`, never `serviceAccountTokenCreator`**, on the workload GSAs – it needs to *launch* things running as them, not *become* them directly, precisely the distinction from Module 8.3. This means a compromised CI pipeline can deploy malicious code that *runs as* `payments-gsa` (a real risk, mitigated by code review/branch protection, outside IAM's scope), but cannot itself directly mint a `payments-gsa` token to exfiltrate data through some unrelated channel.

### 13.2 Reference architecture: CI/CD pipeline (GitHub Actions → GCP, zero keys)

Combining Modules 8 and 10 into one pipeline:

```
GitHub Actions (repo: my-org/payments-service, branch: main)
   │  OIDC token (sub: repo:my-org/payments-service:ref:refs/heads/main)
   ▼
Workload Identity Pool "github-pool" / Provider "github-provider"
   attribute-condition: assertion.repository=='my-org/payments-service' && assertion.ref=='refs/heads/main'
   │  STS token exchange (RFC 8693)
   ▼
Federated principal  --workloadIdentityUser ─▶  GSA: ci-deployer-gsa
   │  generateAccessToken (Module 8)
   ▼
ci-deployer-gsa token, scoped to:
   roles/run.developer (Cloud Run service: payments-service only, via resource condition)
   roles/iam.serviceAccountUser on payments-gsa (so the deployed revision can run as it)
```

Note the layered narrowing at every hop:
* the attribute condition restricts *which workflow runs* can federate at all
* the GSA's own role bindings restrict *what the deploy can touch*
* the `serviceAccountUser`-not-`tokenCreator` distinction (§8.3, applied in §13.1) restricts the deployer to *launching* the runtime identity rather than *becoming* it.

A leaked or maliciously-modified workflow file on a feature branch (not `main`) cannot federate at all, because the attribute condition excludes it – this is the practical payoff of Module 10.4's emphasis on precise attribute conditions.

### 13.3 Reference architecture: data pipeline on BigQuery (Dataflow ingest → BigQuery → analyst access)

```
Cloud Storage (raw landing zone)
   │  read: dataflow-ingest-gsa has storage.objectViewer on this bucket only
   ▼
Dataflow job (runs as dataflow-ingest-gsa, attached identity, no key)
   │  write: dataflow-ingest-gsa has bigquery.dataEditor on dataset "raw_events" only
   ▼
BigQuery dataset: raw_events
   │  scheduled query / dbt job (runs as transform-gsa, separate identity from ingest)
   │  transform-gsa: bigquery.dataViewer on "raw_events" (read) AND bigquery.dataEditor on "curated" (write)
   ▼
BigQuery dataset: curated
   │  analyst access: human analysts in IAM Group "analysts@example.com"
   │  bigquery.dataViewer on "curated" ONLY – never on "raw_events" (may contain raw PII)
   ▼
Analysts (BI tool connects via OAuth user credentials or, for service dashboards,
          a read-only dashboard-gsa with bigquery.dataViewer on curated, impersonated
          by the BI platform via WIF if it supports it, else a tightly-scoped key
          stored in Secret Manager per Module 12)
```

The load-bearing decision here: **3 separate identities** (ingest, transform, analyst-facing) rather than 1 all-purpose "bigquery-sa", each scoped to exactly the dataset(s) its job requires, with raw/PII data never directly exposed to the analyst-facing layer at all – analysts only ever see `curated`. This is least-privilege expressed at the *data pipeline stage* level, not just the IAM-syntax level, and it's the architectural pattern that makes a single compromised identity's blast radius proportional to one pipeline stage rather than the entire warehouse.

### 13.4 Real-world incidents and what they teach

**The "Asset Key Thief" vulnerability (2023, Google Cloud, publicly disclosed and remediated)** – already detailed in Module 7.5. The teaching point repeated here for emphasis: a permission that looked purely observational (`cloudasset.assets.searchAllResources`, bundled in the Cloud Asset Viewer role) turned out to be a path to retrieving private key material for other service accounts under specific conditions, illustrating that **permission risk classification must be re-derived from what a service actually returns, not inferred from a role's name** – "Viewer" roles are not a synonym for "safe."

**Service account key committed to a public GitHub repository ([documented](https://docs.datahub.berkeley.edu/incidents/2019-05-01-service-account-leak.html) public postmortem, UC Berkeley DataHub project, 2019)** – a routine documentation pull request inadvertently included a live service account key with access to the project's Kubernetes clusters and container registry. The organization's own published timeline is notable for what went *right*: Google's automated leaked-credential scanning detected and notified the team **within seconds** of the push, the keys were revoked within roughly 9 minutes of the initial commit, and a full check confirmed no automated credential-scraping bots had exploited the window before revocation. This case is worth studying specifically because it is a **near-miss with a fast, competent response**, not a catastrophic breach – and the team's own action items afterward (stop duplicating key credentials across configurations; move to a different secrets-management strategy entirely) are exactly the Module 7/12 guidance: the root fix wasn't *"rotate faster,"* it was *"stop having a static key in a place it could be committed at all."*

**Stolen service-account tokens enabling lateral movement into production systems (documented in Google's own 2026 Cloud Threat Horizons threat-intelligence reporting, Mandiant-investigated intrusions)** – Google's published threat intelligence has detailed real intrusions in which attackers, having gained an initial foothold, specifically targeted **service account tokens** (rather than human credentials) as the mechanism for lateral movement into sensitive production infrastructure, in some cases reaching workloads running in privileged modes and extending into systems handling identity and financial operations. The pattern documented across these intrusions is consistent with the Module 11.4 escalation chains: an attacker's initial access is rarely the most privileged identity in the environment, and the actual damage tends to come from **finding and using a service account that was more privileged than the entry point**, which is precisely why the controls in Modules 8 and 11 (minimal `serviceAccountUser`/`tokenCreator` grants, delegation-chain logging, anomalous-impersonation detection) exist as a distinct defensive layer from "just secure the perimeter."

The unifying lesson across all these cases: **the service account layer is not a secondary concern behind network/perimeter security – in modern cloud intrusions it is frequently the primary mechanism of lateral movement and privilege escalation**, and the controls in this course (keyless-by-default, narrow and separately-scoped `actAs`/`tokenCreator` grants, mandatory Data Access logging on `iamcredentials.googleapis.com`, deny policies as a backstop against over-granted allow roles) are the direct, specific countermeasures to the techniques actually observed in the wild, not theoretical hygiene.

---

## Module 14 – Capstone: Designing a Secure Multi-Service Platform

* **Learning objectives:** Synthesize all prior modules into a single design exercise with explicit constraints; practice the specific debugging workflow used in production IAM incidents.
* **Prerequisites:** All prior modules.

### 14.1 The brief

You're designing IAM for a platform with: a public-facing API on Cloud Run, a background job pipeline on GKE, a nightly BigQuery ETL job, a CI/CD pipeline on GitHub Actions, and a third-party fraud-detection SaaS that needs read access to a subset of transaction data and only supports static API-key-style auth (no OIDC/SAML support on their end). Work through, on paper, before checking the suggested approach below: how many service accounts you'd create and why; which of them ever hold a key, and how that key is protected; the exact role bound to the CI pipeline's federated identity, and whether it's `serviceAccountUser` or `serviceAccountTokenCreator` on which targets; how you'd detect, within minutes, if the third-party SaaS's credential were used from anywhere other than their documented IP range.

**Suggested approach:** Five SAs – `api-gsa` (Cloud Run, attached identity, no key, scoped to its own dataset/cache only), `worker-gsa` (GKE Workload Identity, no key, scoped to the job queue and its output bucket only), `etl-gsa` (BigQuery job, attached identity via Dataflow/Composer, no key, scoped per Module 13.3's three-tier pattern), `ci-deployer-gsa` (federated via GitHub WIF per Module 10.3, holds `serviceAccountUser` – not `tokenCreator` – on `api-gsa` and `worker-gsa` only, with an attribute condition locked to the `main` branch of the specific deploy repos), and `fraud-saas-gsa` (the one SA in the system holding a JSON key, granted only `bigquery.dataViewer` scoped by condition to a single redacted view rather than the base transactions table, key stored in Secret Manager, org policy enforcing a short max key age, and a standing log-based alert on any `iamcredentials`/BigQuery access from this SA originating outside the vendor's published egress ranges). Every other SA in the system has zero keys and is reachable only through attached identity or WIF.

### 14.2 Troubleshooting workflow (practice this until it's reflexive)

When access "doesn't work" or, worse, "works when it shouldn't," work the problem in this order:

1. **Identify the exact principal and exact permission** actually being checked – don't guess from the error message alone; the failing operation's documentation lists required permissions, and they're sometimes more numerous than expected (a single user-facing action can require permissions on more than one resource, e.g. both the target resource and the SA being attached to it).
2. **Run Policy Troubleshooter** (`gcloud policy-troubleshoot iam`, Module 3.3) against that exact principal/permission/resource triple – this single step resolves the majority of *"why doesn't this work"* cases by showing the actual evaluated bindings and deny rules.
3. **Check for deny policies first**, not last – an allow grant that looks correct but is silently blocked by an org-level deny rule (Module 4) is a common false lead that sends people back to re-checking allow bindings that were never the problem.
4. **Check policy version** if a conditional binding seems to be missing or ignored (Module 3.1) – `--policy-version=3` omissions are extremely common in custom tooling and Terraform modules written before conditions were introduced.
5. **Check propagation timing** (Module 1.3) before assuming a just-applied change is broken – wait a few minutes and recheck.
6. **For impersonation-specific failures**, separately verify: the caller's own underlying credential is valid; the caller holds `serviceAccountTokenCreator` **on the target SA specifically** (not the project); if chained, every hop in the `delegates` list has the matching grant on the next hop; and that Data Access audit logging is even enabled if you're trying to confirm the call happened at all (Module 11.1).
7. **For "attached identity" failures** (metadata server token requests failing), verify the resource actually has the SA attached as intended (a redeploy can silently revert to a default SA if the deploy config omitted the `--service-account` flag), and that the SA itself isn't disabled (Module 5.4).

---

# The Cheat Sheet

### Resource hierarchy & policy evaluation
- Hierarchy: `Organization → Folder(s) → Project → Resource`. Allow policies are inherited **down**, and the effective allow policy at any resource is the **union** of its own bindings plus every ancestor's bindings.
- Evaluation order, every single time: **(1) principal access boundary policies → (2) deny policies → (3) allow policies → (4) default deny.** Deny always wins over allow, including over `roles/owner`.
- Allow-policy inheritance is OR/union – you cannot use a lower-level resource's policy to *remove* an inherited grant. Only a deny policy can do that.
- A `condition` on a binding requires policy schema **version 3**; without explicitly requesting v3, conditional bindings can be silently dropped on read or write.
- Propagation after `setIamPolicy` is eventually consistent platform-wide; budget for up to several minutes before assuming a change has taken full effect everywhere.

### Roles
- **Basic** (`owner`/`editor`/`viewer`) = broad, legacy, avoid in production.
- **Predefined** = Google-curated, can silently gain permissions over time as services evolve.
- **Custom** = you own the exact permission list and its lifecycle; not all permissions are eligible for custom roles (check `SUPPORTED`/`TESTING`/`NOT_SUPPORTED`).
- Read the actual permission list before trusting a role name – `.viewer`/`.editor`/`.admin` naming is convention, not contract.

### Service accounts – identity, not secrets
- A service account is a non-human identity with **dual nature**: a *principal* you bind elsewhere, and a *resource* with its own IAM policy governing who can attach it, impersonate it, or manage its keys.
- `roles/iam.serviceAccountUser` (`actAs`) = **launch things running as** this SA. `roles/iam.serviceAccountTokenCreator` (`getAccessToken`) = **directly mint credentials as** this SA. Never conflate these; grant each to the narrowest audience that needs exactly that capability.
- Deleting a service account is a soft delete with a **30-day undelete window**; after that (or on recreate-with-same-name without undelete), it's a brand-new identity with a new unique ID and zero of the old bindings.
- Disable, don't delete, when responding to a suspected SA compromise – disabling is instant and reversible.

### Tokens & credentials
- **OAuth2 access token** → calling Google APIs. **OIDC ID token** → authenticating to a custom/HTTP service (audience-bound).
- 3 ways an SA gets a usable credential: **(1) attached identity** via the metadata server (fully keyless, Google holds the signing key), **(2) self-signed JWT** from a downloaded private key (the risky, legacy path – RFC 7523 JWT-bearer flow against `oauth2.googleapis.com/token`), **(3) impersonation** via `iamcredentials.googleapis.com` (`generateAccessToken`/`generateIdToken`/`signBlob`/`signJwt` – caller's own credential is the proof, no key needed).
- Default token lifetime: **1 hour**, extendable to **12 hours** only for SAs explicitly allow-listed via org policy.
- ADC resolution order: `GOOGLE_APPLICATION_CREDENTIALS` env var → gcloud user ADC file (dev only) → attached-identity metadata server → failure.

### Keys
- A JSON key is a long-lived bearer credential usable from anywhere on the internet – categorically riskier than every keyless alternative.
- Org policy constraints `iam.disableServiceAccountKeyCreation` and `iam.disableServiceAccountKeyUpload` should be the default posture, not the exception.
- If a key is unavoidable: narrowest possible role, narrowest possible resource scope, max-key-age org policy, stored only in Secret Manager, usage-anomaly alerting by source IP, treated as already-compromised in your threat model.
- Leaked key in source control = sev-1, revoke immediately, don't wait for a *"cleanup ticket."*

### Impersonation & federation
- Chained impersonation (`delegates`) lets C→B→A without C needing any direct grant on A – each hop independently auditable/revocable.
- Workload Identity Federation and GKE Workload Identity both run on the same primitive: **OAuth 2.0 Token Exchange (RFC 8693) via the Security Token Service.**
- The **attribute condition** on a Workload Identity Pool provider is the real security boundary for external federation – scope it to the exact repo/branch/environment, never just an org-wide claim.

### Audit & detection
- **Admin Activity logs** (includes every `SetIamPolicy`, key create/delete) – always on, 400-day retention, cannot be disabled.
- **Data Access logs** (includes every impersonation call to `iamcredentials.googleapis.com`) – **not on by default for many services**; verify it's enabled before you need it.
- `protoPayload.authenticationInfo.serviceAccountDelegationInfo` in an audit log entry shows the full delegation chain, with the original caller at the bottom.

### The six privilege-escalation chains to test for, in every production project
1. `serviceAccountKeyAdmin` on a privileged SA → mint yourself a key.
2. `serviceAccountTokenCreator` on a privileged SA → mint yourself a token directly.
3. Compute/instance-admin permissions + `serviceAccountUser` on a privileged SA → launch a VM as it, pull a token from its metadata server.
4. Cloud Functions/Cloud Run deploy permissions + `serviceAccountUser` on a privileged SA → deploy attacker code running as it.
5. Cloud Build/CI deploy permissions + `serviceAccountUser` on a (often over-privileged-by-default) build runtime SA.
6. `iam.roles.update` on a custom role currently bound to a privileged scope → quietly add permissions, no new binding ever created.

### Secrets vs. identity
- Service accounts answer *"who"*; Secret Manager answers *"how does this verified 'who' safely get a sensitive value it needs."* Never use an SA key as a general-purpose secret-distribution channel.

---

# Decision Tree: User Account vs. Service Account vs. Workload Identity Federation

```
START: Something needs to authenticate to GCP. What is "something"?
│
├─ A specific human, doing interactive work (console, gcloud, BI tool, debugging)
│     └─▶ USER ACCOUNT (their own Google/Workspace identity, ideally via SSO + MFA).
│         Never substitute a shared service account for this – you lose individual
│         attribution in every audit log entry.
│
├─ A workload (app, job, pipeline, function) that runs ON Google Cloud compute
│  (GCE, GKE, Cloud Run, Cloud Functions, Cloud Build, App Engine, Composer, Dataflow)
│     └─▶ SERVICE ACCOUNT, used via ATTACHED IDENTITY (metadata server).
│         No key. No impersonation needed. This is the default, common case.
│         ├─ On GKE specifically? → Use GKE WORKLOAD IDENTITY to bind a distinct
│         │  Kubernetes Service Account per microservice to a distinct GSA –
│         │  do not share one GSA across unrelated workloads in the cluster.
│         └─ Does it need to call ANOTHER of your own HTTP services (not a Google API)?
│            → Also mint an OIDC ID TOKEN (audience = target service URL),
│              not just an OAuth2 access token.
│
├─ A workload that runs OUTSIDE Google Cloud, but can produce a trustworthy
│  OIDC or SAML token from its own identity provider
│  (GitHub Actions, GitLab CI, AWS workload via AWS's own identity, Azure AD,
│   on-prem system with an OIDC IdP)
│     └─▶ WORKLOAD IDENTITY FEDERATION (external).
│         Configure a Workload Identity Pool + Provider, write a TIGHT attribute
│         condition (exact repo/branch/environment – never a bare org-wide claim),
│         and have the federated identity impersonate a narrowly-scoped GSA via
│         roles/iam.workloadIdentityUser. Zero long-lived secrets, full audit trail.
│
├─ A workload outside GCP that CANNOT produce any OIDC/SAML token at all
│  (legacy on-prem system, third-party SaaS that only supports static API-key-style auth)
│     └─▶ Last resort: SERVICE ACCOUNT WITH A JSON KEY.
│         Mandatory mitigations: narrowest possible role on narrowest possible
│         resource scope; key stored only in a secrets manager, never a flat file
│         or repo; org policy enforcing maximum key age; usage-anomaly alerting
│         (e.g. by source IP range); treat the key as already compromised in your
│         threat model from day one.
│
├─ A human or system needs to act AS an existing service account for a specific,
│  bounded task (local dev, break-glass debugging, a central automation tool
│  reaching into many per-team SAs)
│     └─▶ IMPERSONATION (roles/iam.serviceAccountTokenCreator on that SA, scoped
│         to the narrowest possible caller – a named group, not "all engineers").
│         Use --impersonate-service-account / ADC impersonation instead of ever
│         downloading that SA's key for this purpose.
│
└─ A CI/CD pipeline needs to DEPLOY a workload that will later run AS a service account
      └─▶ The PIPELINE's federated identity gets roles/iam.serviceAccountUser
          (actAs) on the target runtime SA – NOT serviceAccountTokenCreator.
          The pipeline should be able to launch things running as that SA;
          it should not be able to directly mint tokens as it for unrelated use.
```

Quick decision tests:
- *"Could I name a specific human responsible for this action?"* → user account.
- *"Is this code, not a person, calling an API?"* → service account, attached identity by default.
- *"Does the caller already have its own IdP-issued token I could trust instead of inventing a new Google secret?"* → Workload Identity Federation.
- *"Am I about to type `gcloud iam service-accounts keys create` because it's the path of least resistance, not because every keyless option was actually ruled out?"* → stop, re-check the tree above.

---

# Advanced Interview Questions

**Q1. Explain, step by step, exactly what happens when a Compute Engine VM with an attached service account calls a Google API. Where does the cryptographic trust actually live?**
The application calls the instance metadata server (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`) with header `Metadata-Flavor: Google`. The metadata server is itself authenticated to a Google-internal credential-issuance backend as "this instance is configured to run as SA X." That backend mints a short-lived OAuth2 access token signed using a private key that Google generates, holds, and rotates entirely internally – it is never exposed to the customer, never downloadable, and never written to disk on the VM. The trust anchor is "Google's infrastructure attests that this specific VM is the one configured to use this SA," not any secret the customer manages – which is exactly why this path is described as fully keyless.

**Q2. A custom role has only 3 permissions. Is it automatically least-privilege? Justify your answer with an example.**
No. Permission *count* is irrelevant; what matters is what those permissions enable in combination with everything else the principal holds. A role containing only `iam.serviceAccounts.actAs` looks minimal, but combined with even a narrowly-scoped permission to create a Compute Engine instance, it lets the holder launch a VM running as any SA they have `actAs` on and pull a token from its metadata server – a full privilege-escalation primitive from two "small" permissions. Least privilege must be evaluated against the full set of a principal's capabilities and plausible escalation chains, not against any single role in isolation.

**Q3. What's the precise difference between `roles/iam.serviceAccountUser` and `roles/iam.serviceAccountTokenCreator`, and why does conflating them create risk?**
`serviceAccountUser` grants `iam.serviceAccounts.actAs` – the ability to attach the SA to a *new resource being created* (a VM, function, Cloud Run revision) so that resource runs as that SA; the holder doesn't get a token directly. `serviceAccountTokenCreator` grants `iam.serviceAccounts.getAccessToken` (plus sibling ID-token/sign permissions) – the ability to directly mint a usable credential as the SA right now, with no resource creation involved at all. Conflating them risks over-granting: a CI deployer that only needs to launch workloads as a runtime SA does not need the ability to directly become that SA for arbitrary out-of-band API calls, and granting `tokenCreator` "to be safe" turns a deploy pipeline into a direct impersonation primitive for that identity.

**Q4. Where is a service account's role binding actually evaluated when it acts as both a principal and a resource – does this ever create a cycle or ambiguity?**
No cycle: these are two distinct policy objects. As a *resource*, the SA has its own IAM policy (`gcloud iam service-accounts get-iam-policy`) governing who can act as/impersonate/manage it – this is evaluated when someone tries to use the SA (attach it, mint a token from it, edit it). As a *principal*, the SA's email appears inside the `members`/principal list of *other* resources' `allow` policies (a project, a bucket, a dataset) – this is evaluated when the SA itself tries to access something. The two checks happen at different points in different request flows and never reference each other recursively; an SA's own resource-level policy says nothing about what the SA itself can do elsewhere.

**Q5. Why does Google document that frequently-rotated service account keys were, in one disclosed vulnerability, counter-intuitively *more* exposed than rarely-rotated ones?**
In the 2023 "Asset Key Thief" disclosure, the vulnerable code path exposed private key material for keys retrievable through Cloud Asset Inventory's resource-search responses under specific conditions tied to how recently/how the key material had been generated and surfaced internally. Organizations rotating keys frequently had more *recently-created* key material that fell within the affected retrieval window at any given time, compared to organizations with old, rarely-touched keys. The general lesson: a mitigation designed for one threat model (reducing the value of a long-lived stolen key by shortening its useful life) doesn't automatically transfer to a different threat model (a platform-level bug exposing key material directly) – the durable fix in that case, and in general, is eliminating static keys rather than rotating them faster.

**Q6. Explain the OAuth2 grant type used when a service account authenticates via a downloaded JSON key.**
It's the **JWT Bearer Token Flow for Server-to-Server Applications**, specified in **RFC 7523**. The client constructs a JWT claim set (`iss`/`sub` = the SA email, `aud` = the token endpoint or a target audience, `scope`, `iat`, `exp` ≤ 1 hour), signs it locally using RS256 with the private key from the JSON file, and POSTs it to `https://oauth2.googleapis.com/token` with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<signed_jwt>`. Google verifies the signature against the public key it retained at key-creation time and, if valid, returns a standard OAuth2 access token.

**Q7. What is the Security Token Service, and how does it relate to both GKE Workload Identity and external Workload Identity Federation?**
The Security Token Service (`sts.googleapis.com`) implements **OAuth 2.0 Token Exchange (RFC 8693)**: given a "subject token" from a trusted external issuer, it returns a Google-recognized federated token representing that external identity. Both GKE Workload Identity and external WIF are built on exactly this primitive – GKE Workload Identity trusts the cluster's own Kubernetes-issued OIDC tokens (one per pod's KSA) as the subject token, while external WIF trusts a configured third-party OIDC/SAML issuer (GitHub, AWS, Azure, on-prem). In both cases the resulting federated token is typically then used to impersonate a Google service account via `generateAccessToken`, rather than being granted roles directly.

**Q8. A deny policy targets the permission `compute.instances.delete` and doesn't seem to block anything. What's the most likely cause?**
Deny policies require **IAM v2 permission identifiers**, of the form `SERVICE_FQDN/RESOURCE.ACTION` – in this case `compute.googleapis.com/instances.delete`, not the v1 dotted form `compute.instances.delete` used in role bindings. A deny rule written with the v1-style string simply fails to match anything, silently providing no protection while looking correct on cursory review.

**Q9. Why must a deny rule check happen before allow-policy evaluation rather than after, from a design-intent standpoint?**
Because the entire purpose of deny policies is to express hard organizational guardrails that hold even against principals who have accumulated excessive allow-policy grants over time – including `roles/owner` itself. If allow were checked first and deny only applied as a tie-breaker or override after, the system would still need deny to win in any conflict, which is logically equivalent to evaluating deny first; but evaluating deny first also lets the system short-circuit and avoid doing unnecessary allow-policy resolution work across a potentially large inherited hierarchy when access is going to be denied regardless.

**Q10. Describe a realistic multi-step privilege escalation chain in a CI/CD context and identify the single IAM change that would have broken it.**
A developer holds `cloudbuild.builds.editor` (to manage build configs) plus `iam.serviceAccountUser` on the Cloud Build default runtime SA – which, in a legacy-configured project, still carries `roles/editor` on the project. The developer submits a build step that does nothing but call `curl` against the Cloud Build job's attached metadata server to fetch an access token for that runtime SA, then uses that token directly against the GCP API to perform actions far beyond their own granted permissions – e.g., reading secrets, modifying IAM policy, exfiltrating data. The single change that breaks this chain: replace the Cloud Build default runtime SA's `roles/editor` binding with a narrowly-scoped custom role containing only the permissions actual build steps legitimately need (e.g., push to Artifact Registry, deploy to a specific Cloud Run service) – the `serviceAccountUser` grant on that SA stops being meaningfully exploitable once the SA itself isn't privileged enough to matter.

**Q11. What does `serviceAccountDelegationInfo` in an audit log entry tell you, and why is it specifically important for impersonation forensics?**
It lists the full chain of identities involved in a delegated/impersonated API call, with the **bottom entry being the original caller who initiated the chain** (a human or a root automation identity), and each subsequent entry being an intermediate SA hop. Without this field, a multi-hop impersonation chain (C impersonates B impersonates A) would show audit log entries attributing the final action only to A, with no visibility into who actually triggered it – making forensic attribution effectively impossible for anything beyond single-hop impersonation. Its presence is what makes deep delegation chains auditable rather than a black box.

**Q12. Why is `allAuthenticatedUsers` dangerous, and how does it differ from a binding scoped to your organization's domain?**
`allAuthenticatedUsers` matches **any principal holding any Google account anywhere**, not just accounts in your Workspace/Cloud Identity domain – effectively *"anyone on the internet who bothers to sign in with a free Google account first."* A binding intended to mean *"anyone at my company"* should use `domain:example.com` instead, which resolves specifically to Cloud Identity/Workspace-managed accounts under that verified domain. Confusing the two has caused real public data-exposure incidents on Cloud Storage buckets, where engineers believed they were scoping access to their org and were in fact granting it to the public internet.

**Q13. How would you design a system so that a leaked CI/CD credential has a blast radius measured in minutes rather than indefinitely?**
Use Workload Identity Federation so the pipeline never holds a static key at all – its proof of identity is a short-lived OIDC token from its own CI provider, exchanged at request time for a Google-federated token that itself expires within roughly an hour. Scope the attribute condition to the exact repo/branch so only legitimate pipeline runs can federate in the first place, and grant the federated identity only `serviceAccountUser` (not `tokenCreator`) on a deploy-target SA whose own role bindings are scoped to the specific service(s) it deploys. Under this design, even a fully leaked CI run's federated token is useless after roughly an hour, cannot be used outside the conditions the attribute condition allows, and cannot be used to directly impersonate the deploy SA for unrelated actions because only `actAs`, not `tokenCreator`, was granted.

**Q14. What's the operational difference between disabling and deleting a suspected-compromised service account, and when would you choose each?**
Disabling is instantaneous and fully reversible: existing keys and tokens for the SA immediately stop working, but the SA object, its role bindings, and its audit history remain intact for investigation, and it can be re-enabled the moment the investigation clears it. Deletion is a soft delete with a 30-day undelete window, after which the identity is permanently gone and any future SA created with the same email is a *different* identity with no inherited bindings. In an active incident, disable first – it achieves the same immediate containment without foreclosing investigation or recovery options, and you can always delete afterward once you're certain the SA should never be used again.

**Q15. Why does Google's own guidance explicitly warn that audit-log Data Access logging for `iamcredentials.googleapis.com` is not guaranteed to be on by default, and what's the practical risk of missing this?**
Admin Activity logs (always on) capture IAM *configuration changes* – who granted what role to whom – but not the *use* of impersonation grants once they exist. Data Access logs, which capture actual `GenerateAccessToken`/`GenerateIdToken` calls, are not universally on by default across services, partly for log-volume/cost reasons. The practical risk: an organization can have a perfectly clean Admin Activity trail (every grant properly reviewed and approved) while having zero visibility into whether those impersonation grants are actually being exercised, by whom, how often, or from where – meaning a misused or quietly-abused `serviceAccountTokenCreator` grant could go undetected indefinitely unless Data Access logging was deliberately enabled and is being actively monitored.

**Q16. In the BigQuery data pipeline pattern, why use 3 separate service accounts (ingest, transform, analyst-facing) instead of 1 shared "bigquery-pipeline-sa"?**
Each stage has a different legitimate access need and a different exposure surface: the ingest SA needs write access to a raw landing dataset that may contain unredacted PII and read access to a storage bucket, the transform SA needs read on raw dataset and write on curated dataset, and the analyst-facing layer needs only read on curated dataset (no rights to raw). A single shared SA would necessarily hold the union of all 3 needs, meaning a compromise at any single stage (e.g., a vulnerability in the BI dashboard layer) would expose write access to raw ingestion and the ability to modify transform logic – far beyond what that stage's actual function requires. Separate SAs make blast radius proportional to which specific stage is compromised, and make audit logs immediately attributable to a specific pipeline stage rather than an undifferentiated *"something touched BigQuery."*

**Q17. A principal has `iam.roles.update` permission on a custom role that is currently bound, at the organization level, to a large group of engineers. Why is this a privilege-escalation path even though the principal never creates a new IAM binding?**
Because editing the *permission set inside* an existing custom role immediately changes the effective permissions of every principal already bound to that role, with no new binding ever created and no `SetIamPolicy` event firing – only a `UpdateRole` event. An attacker (or compromised low-privilege principal) with `iam.roles.update` on a role they're already a member of can quietly add a powerful permission to that role definition, instantly granting it to themselves and everyone else in that group, while audit reviews that focus only on `SetIamPolicy` events (the obvious place to look for *"who got new access"*) miss it entirely. This is precisely why a security review process must also monitor custom role *definition* changes (`CreateRole`/`UpdateRole`), not just policy bindings.

---

## Appendix – Quick-Reference Command Index

```bash
# --- Hierarchy ---
gcloud organizations list
gcloud resource-manager folders list --organization=ORG_ID
gcloud projects get-ancestors PROJECT_ID

# --- Allow policies ---
gcloud projects get-iam-policy PROJECT_ID --format=json
gcloud projects add-iam-policy-binding PROJECT_ID --member=MEMBER --role=ROLE
gcloud projects add-iam-policy-binding PROJECT_ID --member=MEMBER --role=ROLE \
  --condition='expression=EXPR,title=T,description=D'

# --- Deny policies ---
gcloud iam policies create POLICY_ID --attachment-point=ATTACH_POINT \
  --kind=denypolicies --policy-file=deny.json
gcloud iam policies list --attachment-point=ATTACH_POINT --kind=denypolicies

# --- Roles ---
gcloud iam roles describe roles/SOME_PREDEFINED_ROLE
gcloud iam list-testable-permissions //RESOURCE_FQDN
gcloud iam roles create ROLE_ID --project=PROJECT_ID --permissions=PERM1,PERM2 --stage=GA

# --- Service accounts: lifecycle ---
gcloud iam service-accounts create SA_NAME --project=PROJECT_ID
gcloud iam service-accounts disable SA_EMAIL
gcloud iam service-accounts delete SA_EMAIL
gcloud iam service-accounts undelete UNIQUE_ID --project=PROJECT_ID
gcloud iam service-accounts get-iam-policy SA_EMAIL
gcloud iam service-accounts add-iam-policy-binding SA_EMAIL --member=MEMBER --role=ROLE

# --- Keys ---
gcloud iam service-accounts keys create FILE.json --iam-account=SA_EMAIL
gcloud iam service-accounts keys list --iam-account=SA_EMAIL
gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL
gcloud resource-manager org-policies enable-enforce constraints/iam.disableServiceAccountKeyCreation --organization=ORG_ID

# --- Impersonation ---
gcloud auth application-default login --impersonate-service-account=SA_EMAIL
gcloud SOME_COMMAND --impersonate-service-account=SA_EMAIL
gcloud SOME_COMMAND --impersonate-service-account=TARGET_SA --delegate-chain=MIDDLE_SA

# --- Workload Identity Federation ---
gcloud iam workload-identity-pools create POOL_ID --location=global
gcloud iam workload-identity-pools providers create-oidc PROVIDER_ID \
  --workload-identity-pool=POOL_ID --location=global \
  --issuer-uri=ISSUER --attribute-mapping=MAPPING --attribute-condition=CONDITION

# --- Troubleshooting & analysis ---
gcloud policy-troubleshoot iam RESOURCE --principal-email=EMAIL --permission=PERM
gcloud asset search-all-iam-policies --scope=SCOPE --query=QUERY
gcloud asset analyze-iam-policy --organization=ORG_ID --full-resource-name=RESOURCE --permissions=PERM1,PERM2
gcloud recommender recommendations list --project=PROJECT_ID --location=global --recommender=google.iam.policy.Recommender
```

---

## Closing Remarks

The common thread of this course is a single design discipline: **default to no standing secret, scope every grant to the narrowest resource and the narrowest capability, and assume every permission you hand out will eventually be evaluated by an attacker for what it enables in combination with everything else – not in isolation.** Service accounts are where this discipline is tested hardest in practice, because they sit at the exact intersection of *"must be usable by automation with no human in the loop"* and *"must not become a standing, transferable secret that outlives its purpose."* Every mechanism in this course – attached identity, impersonation, Workload Identity Federation, deny policies, conditions – exists to make that intersection survivable at production scale.
