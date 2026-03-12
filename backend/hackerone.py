"""
AutoBB - HackerOne Client
Busca o escopo (in-scope assets) de um programa HackerOne.

Usa o endpoint público https://hackerone.com/graphql com a query
PolicySearchStructuredScopesQuery — exatamente como o browser faz.

Requer apenas:
  H1_SESSION_COOKIE  → valor do cookie __Host-session
  H1_CSRF_TOKEN      → valor do header X-Csrf-Token

Ambos obtidos logando no hackerone.com e inspecionando qualquer requisição
GraphQL no DevTools (Network tab).

Schema Supabase:
  programs (id int8, created_at, program_name text, latest_scope_version_id text)
  → program_name é o handle do HackerOne (ex: 'shopify')
  → latest_scope_version_id é a URL de policy_scopes (usada apenas para log)
"""

from __future__ import annotations

import os
import re
import requests
from dotenv import load_dotenv

load_dotenv()

H1_CSRF_TOKEN = os.getenv("H1_CSRF_TOKEN", "")

H1_GRAPHQL_URL = "https://hackerone.com/graphql"

# Tipos de display_name considerados domínios/URLs escaneáveis
DOMAIN_DISPLAY_TYPES = {"Domain", "Url", "Api", "Wildcard"}


def _clean_domain(identifier: str, keep_wildcard: bool = False) -> str:
    """Remove scheme, path de um identificador de asset.
    Se keep_wildcard=True e o identifier contém *, retorna no formato *.base.tld
    para que o subfinder possa expandir."""
    clean = identifier.strip()
    has_wildcard = "*" in clean
    clean = re.sub(r"^https?://", "", clean)
    clean = clean.split("/")[0]
    clean = clean.split("?")[0]
    if has_wildcard and keep_wildcard:
        # Extrai o domínio base mais profundo sem asteriscos
        # ex: static*.twilio.com → *.twilio.com
        # ex: *.sip.*.twilio.com → *.twilio.com (pega o TLD+1 final)
        parts = clean.split(".")
        # Remove partes que contêm * e pega o sufixo limpo
        clean_parts = []
        for p in reversed(parts):
            if "*" in p:
                break
            clean_parts.insert(0, p)
        if len(clean_parts) >= 2:
            return "*." + ".".join(clean_parts).lower()
        # fallback: remove todos os * e retorna o que sobrou
        base = re.sub(r"\*\.?", "", clean).lstrip(".")
        return ("*." + base).lower() if base else ""
    elif has_wildcard:
        # Remove o wildcard e retorna apenas o domínio base
        parts = clean.split(".")
        clean_parts = [p for p in parts if "*" not in p]
        return ".".join(clean_parts).lower()
    return clean.lower()


def _dedup(domains: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for d in domains:
        if d and d not in seen:
            seen.add(d)
            result.append(d)
    return result


def _build_headers(handle: str) -> dict:
    """Monta os headers exatamente como o browser envia (endpoint público)."""
    return {
        "Content-Type": "application/json",
        "Accept": "*/*",
        "X-Csrf-Token": H1_CSRF_TOKEN,
        "X-Product-Area": "h1_assets",
        "X-Product-Feature": "policy_scopes",
        "Origin": "https://hackerone.com",
        "Referer": f"https://hackerone.com/{handle}/policy_scopes",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/138.0.0.0 Safari/537.36"
        ),
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    }


# Query exata capturada do browser
_SCOPE_QUERY = """
query PolicySearchStructuredScopesQuery(
  $handle: String!,
  $searchString: String,
  $eligibleForSubmission: Boolean,
  $eligibleForBounty: Boolean,
  $asmTagIds: [Int],
  $assetTypes: [StructuredScopeAssetTypeEnum!],
  $from: Int,
  $size: Int,
  $sort: SortInput
) {
  team(handle: $handle) {
    id
    structured_scopes_search(
      search_string: $searchString
      eligible_for_submission: $eligibleForSubmission
      eligible_for_bounty: $eligibleForBounty
      asm_tag_ids: $asmTagIds
      asset_types: $assetTypes
      from: $from
      size: $size
      sort: $sort
    ) {
      nodes {
        ... on StructuredScopeDocument {
          id
          identifier
          display_name
          instruction
          cvss_score
          eligible_for_bounty
          eligible_for_submission
          created_at
          updated_at
          __typename
        }
        __typename
      }
      pageInfo {
        startCursor
        hasPreviousPage
        endCursor
        hasNextPage
        __typename
      }
      total_count
      __typename
    }
    __typename
  }
}
"""


def _fetch_page(handle: str, from_: int, size: int = 100) -> dict:
    """Faz uma requisição de uma página de scope."""
    payload = {
        "operationName": "PolicySearchStructuredScopesQuery",
        "variables": {
            "handle": handle,
            "searchString": "",
            "eligibleForSubmission": True,   # só in-scope
            "eligibleForBounty": None,
            "asmTagIds": [],
            "assetTypes": [],
            "from": from_,
            "size": size,
            "sort": {"field": "cvss_score", "direction": "DESC"},
            "product_area": "h1_assets",
            "product_feature": "policy_scopes",
        },
        "query": _SCOPE_QUERY,
    }

    resp = requests.post(
        H1_GRAPHQL_URL,
        json=payload,
        headers=_build_headers(handle),
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def get_program_scope(handle: str, scope_url: str = "") -> list[str]:
    """
    Retorna lista de domínios únicos in-scope de um programa HackerOne.
    Usa a query PolicySearchStructuredScopesQuery com paginação automática.

    Params:
        handle    — program_name do Supabase (ex: 'clear', 'shopify')
        scope_url — latest_scope_version_id (usado apenas para log)
    """
    if not H1_CSRF_TOKEN:
        print("[H1] AVISO: H1_CSRF_TOKEN não configurado — tentando mesmo assim (endpoint público)")


    if scope_url:
        print(f"[H1] scope_url: {scope_url}")

    print(f"[H1] Buscando scope de '{handle}'...")

    domains: list[str] = []
    page_size = 100
    from_ = 0

    while True:
        try:
            data = _fetch_page(handle, from_=from_, size=page_size)
        except requests.RequestException as e:
            print(f"[H1] Erro na requisição para '{handle}' (from={from_}): {e}")
            break

        errors = data.get("errors")
        if errors:
            print(f"[H1] GraphQL errors para '{handle}': {errors}")
            break

        search = (
            data.get("data", {})
                .get("team", {})
                .get("structured_scopes_search", {})
        )

        if not search:
            print(f"[H1] Programa '{handle}' não encontrado ou sem escopo público.")
            break

        nodes = search.get("nodes", [])
        total = search.get("total_count", 0)

        for node in nodes:
            if node.get("__typename") != "StructuredScopeDocument":
                continue
            if not node.get("eligible_for_submission", False):
                continue

            identifier   = node.get("identifier", "").strip()
            display_name = node.get("display_name", "")

            # Filtra apenas assets do tipo domínio/URL/API
            if display_name not in DOMAIN_DISPLAY_TYPES:
                continue

            # Preserva *. em wildcards para o subfinder expandir depois
            is_wildcard = display_name == "Wildcard" or "*" in identifier
            d = _clean_domain(identifier, keep_wildcard=is_wildcard)
            # Descarta identificadores vazios ou sem ponto no domínio base
            base_check = d.lstrip("*.") if d.startswith("*.") else d
            if d and "." in base_check:
                domains.append(d)

        from_ += page_size
        page_info = search.get("pageInfo", {})
        has_next  = page_info.get("hasNextPage", False)

        print(f"[H1] '{handle}': {len(nodes)} nós recebidos | total={total} | hasNextPage={has_next}")

        if not has_next or from_ >= total:
            break

    unique = _dedup(domains)
    print(f"[H1] '{handle}' → {len(unique)} domínios únicos elegíveis")
    return unique
